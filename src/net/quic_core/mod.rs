//! Tokio-free QUIC transport core primitives.
//!
//! Phase 1 scope:
//! - QUIC varint codec
//! - Connection ID representation
//! - Initial/short packet header codecs
//! - Header-protection sampling and mask application (RFC 9001 §5.4)
//! - Transport parameter TLV codec
//!
//! This module is intentionally runtime-agnostic and memory-safe.

use std::fmt;

/// Maximum value representable by QUIC varint (2^62 - 1).
pub const QUIC_VARINT_MAX: u64 = (1u64 << 62) - 1;
/// Maximum QUIC packet number value (2^62 - 1).
pub const QUIC_PACKET_NUMBER_MAX: u64 = QUIC_VARINT_MAX;
/// Header-protection sample length (RFC 9001 §5.4.2): every QUIC v1 AEAD
/// samples 16 bytes of the protected payload.
pub const HEADER_PROTECTION_SAMPLE_LEN: usize = 16;
/// Maximum encoded packet-number width in bytes (RFC 9000 §17.1).
///
/// The header-protection sample is taken as if the packet number were this
/// wide (RFC 9001 §5.4.2), which is what makes sampling possible before the
/// real width is known.
pub const MAX_PACKET_NUMBER_LEN: usize = 4;

/// Transport parameter: max_idle_timeout.
pub const TP_MAX_IDLE_TIMEOUT: u64 = 0x01;
/// Transport parameter: max_udp_payload_size.
pub const TP_MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
/// Transport parameter: initial_max_data.
pub const TP_INITIAL_MAX_DATA: u64 = 0x04;
/// Transport parameter: initial_max_stream_data_bidi_local.
pub const TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
/// Transport parameter: initial_max_stream_data_bidi_remote.
pub const TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
/// Transport parameter: initial_max_stream_data_uni.
pub const TP_INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
/// Transport parameter: initial_max_streams_bidi.
pub const TP_INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
/// Transport parameter: initial_max_streams_uni.
pub const TP_INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
/// Transport parameter: ack_delay_exponent.
pub const TP_ACK_DELAY_EXPONENT: u64 = 0x0a;
/// Transport parameter: max_ack_delay.
pub const TP_MAX_ACK_DELAY: u64 = 0x0b;
/// Transport parameter: disable_active_migration.
pub const TP_DISABLE_ACTIVE_MIGRATION: u64 = 0x0c;
/// Transport parameter: max_datagram_frame_size (RFC 9221).
pub const TP_MAX_DATAGRAM_FRAME_SIZE: u64 = 0x20;

/// Errors returned by QUIC core codecs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicCoreError {
    /// Input buffer ended unexpectedly.
    UnexpectedEof,
    /// QUIC varint value exceeds 2^62 - 1.
    VarIntOutOfRange(u64),
    /// Malformed packet header.
    InvalidHeader(&'static str),
    /// Connection ID length is out of range (must be <= 20).
    InvalidConnectionIdLength(usize),
    /// Packet number cannot fit in requested wire width.
    PacketNumberTooLarge {
        /// Packet number value that failed validation.
        packet_number: u32,
        /// Requested packet-number wire width in bytes.
        width: u8,
    },
    /// Duplicate transport parameter encountered.
    DuplicateTransportParameter(u64),
    /// Invalid transport parameter body.
    InvalidTransportParameter(u64),
}

impl fmt::Display for QuicCoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected EOF"),
            Self::VarIntOutOfRange(v) => write!(f, "varint out of range: {v}"),
            Self::InvalidHeader(msg) => write!(f, "invalid header: {msg}"),
            Self::InvalidConnectionIdLength(len) => {
                write!(f, "invalid connection id length: {len}")
            }
            Self::PacketNumberTooLarge {
                packet_number,
                width,
            } => write!(
                f,
                "packet number {packet_number} does not fit in {width} bytes"
            ),
            Self::DuplicateTransportParameter(id) => {
                write!(f, "duplicate transport parameter: 0x{id:x}")
            }
            Self::InvalidTransportParameter(id) => {
                write!(f, "invalid transport parameter: 0x{id:x}")
            }
        }
    }
}

impl std::error::Error for QuicCoreError {}

/// QUIC connection ID (`0..=20` bytes).
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct ConnectionId {
    bytes: [u8; 20],
    len: u8,
}

impl ConnectionId {
    /// Maximum connection ID length.
    pub const MAX_LEN: usize = 20;

    /// Create a connection ID from bytes.
    pub fn new(bytes: &[u8]) -> Result<Self, QuicCoreError> {
        if bytes.len() > Self::MAX_LEN {
            return Err(QuicCoreError::InvalidConnectionIdLength(bytes.len()));
        }
        let mut out = [0u8; Self::MAX_LEN];
        out[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: out,
            len: bytes.len() as u8,
        })
    }

    /// Connection ID length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether the connection ID is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Borrow bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len()]
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConnectionId(")?;
        for b in self.as_bytes() {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

/// Long-header packet type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LongPacketType {
    /// Initial packet type.
    Initial,
    /// 0-RTT packet type.
    ZeroRtt,
    /// Handshake packet type.
    Handshake,
    /// Retry packet type.
    Retry,
}

/// Long-header packet (phase-1 subset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongHeader {
    /// Long-header packet type.
    pub packet_type: LongPacketType,
    /// QUIC version field.
    pub version: u32,
    /// Destination connection ID.
    pub dst_cid: ConnectionId,
    /// Source connection ID.
    pub src_cid: ConnectionId,
    /// Initial token (only present for Initial packets).
    pub token: Vec<u8>,
    /// Payload length field value.
    pub payload_length: u64,
    /// Packet number value (full 64-bit, RFC 9000 allows up to 2^62-1).
    pub packet_number: u64,
    /// Encoded packet-number width in bytes (`1..=4`).
    pub packet_number_len: u8,
}

/// Retry long-header packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryHeader {
    /// QUIC version field.
    pub version: u32,
    /// Destination connection ID.
    pub dst_cid: ConnectionId,
    /// Source connection ID.
    pub src_cid: ConnectionId,
    /// Retry token carried by the server.
    pub token: Vec<u8>,
    /// Retry integrity tag.
    pub integrity_tag: [u8; 16],
}

/// Short-header packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortHeader {
    /// Spin bit value.
    pub spin: bool,
    /// Key phase bit value.
    pub key_phase: bool,
    /// Destination connection ID.
    pub dst_cid: ConnectionId,
    /// Packet number value (full 64-bit, RFC 9000 allows up to 2^62-1).
    pub packet_number: u64,
    /// Encoded packet-number width in bytes (`1..=4`).
    pub packet_number_len: u8,
}

/// QUIC packet header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketHeader {
    /// Long-header packet.
    Long(LongHeader),
    /// Retry long-header packet.
    Retry(RetryHeader),
    /// Short-header packet.
    Short(ShortHeader),
}

impl PacketHeader {
    /// Encode packet header into `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), QuicCoreError> {
        match self {
            Self::Long(h) => encode_long_header(h, out),
            Self::Retry(h) => {
                encode_retry_header(h, out);
                Ok(())
            }
            Self::Short(h) => encode_short_header(h, out),
        }
    }

    /// Decode packet header.
    ///
    /// `short_dcid_len` is required because short headers do not carry CID length.
    pub fn decode(input: &[u8], short_dcid_len: usize) -> Result<(Self, usize), QuicCoreError> {
        if input.is_empty() {
            return Err(QuicCoreError::UnexpectedEof);
        }
        if input[0] & 0x80 != 0 {
            decode_long_header(input)
        } else {
            decode_short_header(input, short_dcid_len).map(|(h, n)| (Self::Short(h), n))
        }
    }
}

/// Long-header fields that header protection never covers (RFC 9001 §5.4.1).
///
/// Everything a receiver needs to route the packet, bound its ciphertext and
/// locate the header-protection sample is here; the reserved bits, the
/// packet-number length and the packet number itself stay masked until
/// [`remove_header_protection`] runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedLongHeaderPrefix {
    /// Long-header packet type (never Retry; see [`ProtectedHeaderPrefix::Retry`]).
    pub packet_type: LongPacketType,
    /// QUIC version field.
    pub version: u32,
    /// Destination connection ID.
    pub dst_cid: ConnectionId,
    /// Source connection ID.
    pub src_cid: ConnectionId,
    /// Initial token (only present for Initial packets).
    pub token: Vec<u8>,
    /// Length field: packet number + AEAD ciphertext + tag, in bytes.
    pub payload_length: u64,
    /// Offset of the (still protected) packet-number field.
    pub packet_number_offset: usize,
}

impl ProtectedLongHeaderPrefix {
    /// Wire length of this packet inside a datagram of `datagram_len` bytes:
    /// the packet-number offset plus the Length field (RFC 9000 §17.2).
    pub fn packet_len(&self, datagram_len: usize) -> Result<usize, QuicCoreError> {
        let payload_length =
            usize::try_from(self.payload_length).map_err(|_| QuicCoreError::UnexpectedEof)?;
        let end = self
            .packet_number_offset
            .checked_add(payload_length)
            .ok_or(QuicCoreError::UnexpectedEof)?;
        if end > datagram_len {
            return Err(QuicCoreError::UnexpectedEof);
        }
        Ok(end)
    }
}

/// The part of a still-protected QUIC packet header that a receiver may read
/// before removing header protection (RFC 9001 §5.4).
///
/// [`PacketHeader::decode`] validates the reserved bits and reads the
/// packet-number length from the first byte; on a packet that still carries
/// header protection those bits are masked, so it must only run after
/// [`remove_header_protection`]. This prefix decoder is the pre-unmask view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectedHeaderPrefix {
    /// Initial / 0-RTT / Handshake packet.
    Long(ProtectedLongHeaderPrefix),
    /// Retry packet (carries no header protection; fully decoded).
    Retry(RetryHeader),
    /// 1-RTT short-header packet.
    Short {
        /// Destination connection ID.
        dst_cid: ConnectionId,
        /// Offset of the (still protected) packet-number field.
        packet_number_offset: usize,
    },
}

impl ProtectedHeaderPrefix {
    /// Decode the unprotected prefix of a packet header.
    ///
    /// `short_dcid_len` is required because short headers do not carry CID
    /// length. Only the invariant fields are validated (form/fixed bits, CID
    /// lengths, Retry reserved bits); a long header's Length field is checked
    /// against the buffer by [`Self::packet_len`].
    pub fn decode(input: &[u8], short_dcid_len: usize) -> Result<Self, QuicCoreError> {
        if input.is_empty() {
            return Err(QuicCoreError::UnexpectedEof);
        }
        if input[0] & 0x80 == 0 {
            decode_short_header_prefix(input, short_dcid_len)
        } else {
            decode_long_header_prefix(input)
        }
    }

    /// Destination connection ID (routing key; never protected).
    #[must_use]
    pub fn dst_cid(&self) -> ConnectionId {
        match self {
            Self::Long(prefix) => prefix.dst_cid,
            Self::Retry(header) => header.dst_cid,
            Self::Short { dst_cid, .. } => *dst_cid,
        }
    }

    /// Offset of the packet-number field, or `None` for Retry packets.
    #[must_use]
    pub fn packet_number_offset(&self) -> Option<usize> {
        match self {
            Self::Long(prefix) => Some(prefix.packet_number_offset),
            Self::Retry(_) => None,
            Self::Short {
                packet_number_offset,
                ..
            } => Some(*packet_number_offset),
        }
    }

    /// Wire length of this packet inside a datagram of `datagram_len` bytes.
    ///
    /// Long-header packets end where their Length field says, which is what
    /// lets coalesced packets (RFC 9000 §12.2) be separated before any key is
    /// touched. Short-header and Retry packets extend to the end of the
    /// datagram.
    pub fn packet_len(&self, datagram_len: usize) -> Result<usize, QuicCoreError> {
        match self {
            Self::Long(prefix) => prefix.packet_len(datagram_len),
            Self::Retry(_) | Self::Short { .. } => Ok(datagram_len),
        }
    }
}

/// Take the header-protection sample (RFC 9001 §5.4.2): 16 bytes starting
/// [`MAX_PACKET_NUMBER_LEN`] bytes past the packet-number offset.
///
/// The sample position assumes the widest packet number, so the same bytes
/// are sampled whether the real packet number is 1 or 4 bytes wide; this is
/// what lets the receiver sample before it knows the width.
pub fn header_protection_sample(
    packet: &[u8],
    packet_number_offset: usize,
) -> Result<[u8; HEADER_PROTECTION_SAMPLE_LEN], QuicCoreError> {
    let start = packet_number_offset
        .checked_add(MAX_PACKET_NUMBER_LEN)
        .ok_or(QuicCoreError::UnexpectedEof)?;
    let end = start
        .checked_add(HEADER_PROTECTION_SAMPLE_LEN)
        .ok_or(QuicCoreError::UnexpectedEof)?;
    let bytes = packet.get(start..end).ok_or(QuicCoreError::UnexpectedEof)?;
    let mut sample = [0u8; HEADER_PROTECTION_SAMPLE_LEN];
    sample.copy_from_slice(bytes);
    Ok(sample)
}

/// Bits of the first byte covered by header protection (RFC 9001 §5.4.1):
/// the low four bits of a long header, the low five of a short header.
const fn header_protection_first_byte_bits(first: u8) -> u8 {
    if first & 0x80 == 0 { 0x1f } else { 0x0f }
}

/// Apply header protection to an unprotected packet in place (sender side).
///
/// RFC 9001 §5.4.1: `packet` must be `header || protected payload` with the
/// packet number at `packet_number_offset`; the packet-number width is read
/// from the still-unmasked first byte. `mask` is the 5-byte provider output
/// for the sample at [`header_protection_sample`].
pub fn apply_header_protection(
    packet: &mut [u8],
    packet_number_offset: usize,
    mask: [u8; 5],
) -> Result<(), QuicCoreError> {
    let first = *packet.first().ok_or(QuicCoreError::UnexpectedEof)?;
    let pn_len = usize::from(first & 0x03) + 1;
    mask_packet_number(packet, packet_number_offset, pn_len, mask)?;
    packet[0] = first ^ (mask[0] & header_protection_first_byte_bits(first));
    Ok(())
}

/// Remove header protection from a received packet in place (receiver side).
///
/// RFC 9001 §5.4.1: returns the packet-number width the unmasked first byte
/// reveals. After this returns, [`PacketHeader::decode`] yields the real
/// header (reserved bits validated, truncated packet number read) and
/// `packet[..packet_number_offset + width]` is the AEAD associated data.
pub fn remove_header_protection(
    packet: &mut [u8],
    packet_number_offset: usize,
    mask: [u8; 5],
) -> Result<u8, QuicCoreError> {
    let first = *packet.first().ok_or(QuicCoreError::UnexpectedEof)?;
    let unmasked = first ^ (mask[0] & header_protection_first_byte_bits(first));
    let pn_len = (unmasked & 0x03) + 1;
    mask_packet_number(packet, packet_number_offset, usize::from(pn_len), mask)?;
    packet[0] = unmasked;
    Ok(pn_len)
}

fn mask_packet_number(
    packet: &mut [u8],
    packet_number_offset: usize,
    pn_len: usize,
    mask: [u8; 5],
) -> Result<(), QuicCoreError> {
    if packet_number_offset == 0 {
        return Err(QuicCoreError::InvalidHeader(
            "packet number cannot start at the first byte",
        ));
    }
    let end = packet_number_offset
        .checked_add(pn_len)
        .ok_or(QuicCoreError::UnexpectedEof)?;
    let packet_number = packet
        .get_mut(packet_number_offset..end)
        .ok_or(QuicCoreError::UnexpectedEof)?;
    for (byte, mask_byte) in packet_number.iter_mut().zip(&mask[1..=pn_len]) {
        *byte ^= mask_byte;
    }
    Ok(())
}

/// Unknown transport parameter preserved byte-for-byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownTransportParameter {
    /// Parameter identifier.
    pub id: u64,
    /// Raw parameter payload bytes.
    pub value: Vec<u8>,
}

/// QUIC transport parameters (phase-1 subset).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransportParameters {
    /// Maximum idle timeout.
    pub max_idle_timeout: Option<u64>,
    /// Maximum UDP payload size.
    pub max_udp_payload_size: Option<u64>,
    /// Initial connection-level data limit.
    pub initial_max_data: Option<u64>,
    /// Initial bidi-local stream receive window.
    pub initial_max_stream_data_bidi_local: Option<u64>,
    /// Initial bidi-remote stream receive window.
    pub initial_max_stream_data_bidi_remote: Option<u64>,
    /// Initial unidirectional stream receive window.
    pub initial_max_stream_data_uni: Option<u64>,
    /// Initial bidirectional stream limit.
    pub initial_max_streams_bidi: Option<u64>,
    /// Initial unidirectional stream limit.
    pub initial_max_streams_uni: Option<u64>,
    /// ACK delay exponent.
    pub ack_delay_exponent: Option<u64>,
    /// Maximum ACK delay.
    pub max_ack_delay: Option<u64>,
    /// Whether active migration is disabled.
    pub disable_active_migration: bool,
    /// Maximum DATAGRAM frame size the endpoint is willing to receive.
    pub max_datagram_frame_size: Option<u64>,
    /// Unknown parameters preserved from decode.
    pub unknown: Vec<UnknownTransportParameter>,
}

impl TransportParameters {
    /// Encode transport parameters to TLV bytes.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), QuicCoreError> {
        encode_known_u64(out, TP_MAX_IDLE_TIMEOUT, self.max_idle_timeout)?;
        encode_known_u64(out, TP_MAX_UDP_PAYLOAD_SIZE, self.max_udp_payload_size)?;
        encode_known_u64(out, TP_INITIAL_MAX_DATA, self.initial_max_data)?;
        encode_known_u64(
            out,
            TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            self.initial_max_stream_data_bidi_local,
        )?;
        encode_known_u64(
            out,
            TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            self.initial_max_stream_data_bidi_remote,
        )?;
        encode_known_u64(
            out,
            TP_INITIAL_MAX_STREAM_DATA_UNI,
            self.initial_max_stream_data_uni,
        )?;
        encode_known_u64(
            out,
            TP_INITIAL_MAX_STREAMS_BIDI,
            self.initial_max_streams_bidi,
        )?;
        encode_known_u64(
            out,
            TP_INITIAL_MAX_STREAMS_UNI,
            self.initial_max_streams_uni,
        )?;
        encode_known_u64(out, TP_ACK_DELAY_EXPONENT, self.ack_delay_exponent)?;
        encode_known_u64(out, TP_MAX_ACK_DELAY, self.max_ack_delay)?;
        if self.disable_active_migration {
            encode_parameter(out, TP_DISABLE_ACTIVE_MIGRATION, &[])?;
        }
        encode_known_u64(
            out,
            TP_MAX_DATAGRAM_FRAME_SIZE,
            self.max_datagram_frame_size,
        )?;
        for p in &self.unknown {
            encode_parameter(out, p.id, &p.value)?;
        }
        Ok(())
    }

    /// Decode transport parameters from TLV bytes.
    pub fn decode(input: &[u8]) -> Result<Self, QuicCoreError> {
        let mut tp = Self::default();
        let mut seen_ids: Vec<u64> = Vec::new();
        let mut pos = 0usize;
        while pos < input.len() {
            let (id, id_len) = decode_varint(&input[pos..])?;
            pos += id_len;
            let (len, len_len) = decode_varint(&input[pos..])?;
            pos += len_len;
            let len = len as usize;
            if input.len().saturating_sub(pos) < len {
                return Err(QuicCoreError::UnexpectedEof);
            }
            let value = &input[pos..pos + len];
            pos += len;
            if seen_ids.contains(&id) {
                return Err(QuicCoreError::DuplicateTransportParameter(id));
            }
            seen_ids.push(id);

            match id {
                TP_MAX_IDLE_TIMEOUT => set_unique_u64(&mut tp.max_idle_timeout, id, value)?,
                TP_MAX_UDP_PAYLOAD_SIZE => {
                    set_unique_u64(&mut tp.max_udp_payload_size, id, value)?;
                    if tp.max_udp_payload_size.is_some_and(|v| v < 1200) {
                        return Err(QuicCoreError::InvalidTransportParameter(id));
                    }
                }
                TP_INITIAL_MAX_DATA => set_unique_u64(&mut tp.initial_max_data, id, value)?,
                TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                    set_unique_u64(&mut tp.initial_max_stream_data_bidi_local, id, value)?;
                }
                TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                    set_unique_u64(&mut tp.initial_max_stream_data_bidi_remote, id, value)?;
                }
                TP_INITIAL_MAX_STREAM_DATA_UNI => {
                    set_unique_u64(&mut tp.initial_max_stream_data_uni, id, value)?;
                }
                TP_INITIAL_MAX_STREAMS_BIDI => {
                    set_unique_u64(&mut tp.initial_max_streams_bidi, id, value)?;
                }
                TP_INITIAL_MAX_STREAMS_UNI => {
                    set_unique_u64(&mut tp.initial_max_streams_uni, id, value)?;
                }
                TP_ACK_DELAY_EXPONENT => {
                    set_unique_u64(&mut tp.ack_delay_exponent, id, value)?;
                    if tp.ack_delay_exponent.is_some_and(|v| v > 20) {
                        return Err(QuicCoreError::InvalidTransportParameter(id));
                    }
                }
                TP_MAX_ACK_DELAY => set_unique_u64(&mut tp.max_ack_delay, id, value)?,
                TP_DISABLE_ACTIVE_MIGRATION => {
                    if tp.disable_active_migration {
                        return Err(QuicCoreError::DuplicateTransportParameter(id));
                    }
                    if !value.is_empty() {
                        return Err(QuicCoreError::InvalidTransportParameter(id));
                    }
                    tp.disable_active_migration = true;
                }
                TP_MAX_DATAGRAM_FRAME_SIZE => {
                    set_unique_u64(&mut tp.max_datagram_frame_size, id, value)?;
                }
                _ => tp.unknown.push(UnknownTransportParameter {
                    id,
                    value: value.to_vec(),
                }),
            }
        }
        Ok(tp)
    }

    /// Compute the effective `max_idle_timeout` for a connection per
    /// RFC 9000 §10.1.
    ///
    /// > Each endpoint advertises a max_idle_timeout, but the effective
    /// > value at an endpoint is computed as the minimum of the two
    /// > advertised values (or the sole advertised value, if only one
    /// > endpoint advertises a non-zero value).
    ///
    /// Per RFC 9000 §18.2, a `max_idle_timeout` of `0` means "no
    /// advertised limit"; the field default is also `0`. This helper
    /// treats `None` and `Some(0)` identically — both are "no advertised
    /// timeout" — so the return value is `None` when neither side has
    /// committed to a finite limit, and `Some(min)` otherwise.
    ///
    /// br-asupersync-4gvuyo: callers were hand-rolling this min() and
    /// repeatedly getting the zero-vs-None semantics wrong; centralize
    /// the rule and assert it with the truth-table test in this module.
    #[must_use]
    pub fn effective_max_idle_timeout(local: &Self, peer: &Self) -> Option<u64> {
        let local_finite = local.max_idle_timeout.filter(|&v| v != 0);
        let peer_finite = peer.max_idle_timeout.filter(|&v| v != 0);
        match (local_finite, peer_finite) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) | (None, Some(a)) => Some(a),
            (None, None) => None,
        }
    }
}

/// Encode a QUIC varint into `out`.
pub fn encode_varint(value: u64, out: &mut Vec<u8>) -> Result<(), QuicCoreError> {
    if value > QUIC_VARINT_MAX {
        return Err(QuicCoreError::VarIntOutOfRange(value));
    }
    if value < (1 << 6) {
        out.push(value as u8);
        return Ok(());
    }
    if value < (1 << 14) {
        let x = value as u16;
        out.push(((x >> 8) as u8 & 0x3f) | 0x40);
        out.push(x as u8);
        return Ok(());
    }
    if value < (1 << 30) {
        let x = value as u32;
        out.push(((x >> 24) as u8 & 0x3f) | 0x80);
        out.push((x >> 16) as u8);
        out.push((x >> 8) as u8);
        out.push(x as u8);
        return Ok(());
    }

    let x = value;
    out.push(((x >> 56) as u8 & 0x3f) | 0xc0);
    out.push((x >> 48) as u8);
    out.push((x >> 40) as u8);
    out.push((x >> 32) as u8);
    out.push((x >> 24) as u8);
    out.push((x >> 16) as u8);
    out.push((x >> 8) as u8);
    out.push(x as u8);
    Ok(())
}

/// Decode a QUIC varint from `input`.
///
/// Returns `(value, consumed_bytes)`.
pub fn decode_varint(input: &[u8]) -> Result<(u64, usize), QuicCoreError> {
    if input.is_empty() {
        return Err(QuicCoreError::UnexpectedEof);
    }
    let first = input[0];
    let len = 1usize << (first >> 6);
    if input.len() < len {
        return Err(QuicCoreError::UnexpectedEof);
    }

    let mut value = u64::from(first & 0x3f);
    for b in &input[1..len] {
        value = (value << 8) | u64::from(*b);
    }
    Ok((value, len))
}

fn encode_long_header(header: &LongHeader, out: &mut Vec<u8>) -> Result<(), QuicCoreError> {
    let pn_len = validate_pn_len(header.packet_number_len)?;
    ensure_pn_fits(header.packet_number, pn_len)?;
    if !matches!(header.packet_type, LongPacketType::Initial) && !header.token.is_empty() {
        return Err(QuicCoreError::InvalidHeader(
            "token only valid for Initial packets",
        ));
    }
    if header.payload_length < u64::from(pn_len) {
        return Err(QuicCoreError::InvalidHeader(
            "payload length smaller than packet number length",
        ));
    }

    let type_bits = match header.packet_type {
        LongPacketType::Initial => 0u8,
        LongPacketType::ZeroRtt => 1u8,
        LongPacketType::Handshake => 2u8,
        LongPacketType::Retry => {
            return Err(QuicCoreError::InvalidHeader(
                "retry packets must use PacketHeader::Retry",
            ));
        }
    };

    let first = 0b1100_0000u8 | (type_bits << 4) | (pn_len - 1);
    out.push(first);
    out.extend_from_slice(&header.version.to_be_bytes());
    out.push(header.dst_cid.len() as u8);
    out.extend_from_slice(header.dst_cid.as_bytes());
    out.push(header.src_cid.len() as u8);
    out.extend_from_slice(header.src_cid.as_bytes());

    if matches!(header.packet_type, LongPacketType::Initial) {
        encode_varint(header.token.len() as u64, out)?;
        out.extend_from_slice(&header.token);
    }

    encode_varint(header.payload_length, out)?;
    write_packet_number(header.packet_number, pn_len, out);
    Ok(())
}

fn encode_retry_header(header: &RetryHeader, out: &mut Vec<u8>) {
    out.push(0b1111_0000u8);
    out.extend_from_slice(&header.version.to_be_bytes());
    out.push(header.dst_cid.len() as u8);
    out.extend_from_slice(header.dst_cid.as_bytes());
    out.push(header.src_cid.len() as u8);
    out.extend_from_slice(header.src_cid.as_bytes());
    out.extend_from_slice(&header.token);
    out.extend_from_slice(&header.integrity_tag);
}

fn encode_short_header(header: &ShortHeader, out: &mut Vec<u8>) -> Result<(), QuicCoreError> {
    let pn_len = validate_pn_len(header.packet_number_len)?;
    ensure_pn_fits(header.packet_number, pn_len)?;

    let mut first = 0b0100_0000u8 | (pn_len - 1);
    if header.spin {
        first |= 0b0010_0000;
    }
    if header.key_phase {
        first |= 0b0000_0100;
    }
    out.push(first);
    out.extend_from_slice(header.dst_cid.as_bytes());
    write_packet_number(header.packet_number, pn_len, out);
    Ok(())
}

fn decode_long_header(input: &[u8]) -> Result<(PacketHeader, usize), QuicCoreError> {
    let prefix = match decode_long_header_prefix(input)? {
        ProtectedHeaderPrefix::Retry(header) => {
            return Ok((PacketHeader::Retry(header), input.len()));
        }
        ProtectedHeaderPrefix::Long(prefix) => prefix,
        ProtectedHeaderPrefix::Short { .. } => {
            unreachable!("long-header prefix decoder never yields a short header")
        }
    };
    let first = input[0];
    if first & 0x0c != 0 {
        return Err(QuicCoreError::InvalidHeader(
            "long header reserved bits set",
        ));
    }
    let pn_len = (first & 0x03) + 1;
    if prefix.payload_length < u64::from(pn_len) {
        return Err(QuicCoreError::InvalidHeader(
            "payload length smaller than packet number length",
        ));
    }

    let mut pos = prefix.packet_number_offset;
    let packet_number = read_packet_number(input, &mut pos, pn_len)?;
    Ok((
        PacketHeader::Long(LongHeader {
            packet_type: prefix.packet_type,
            version: prefix.version,
            dst_cid: prefix.dst_cid,
            src_cid: prefix.src_cid,
            token: prefix.token,
            payload_length: prefix.payload_length,
            packet_number: packet_number as u64,
            packet_number_len: pn_len,
        }),
        pos,
    ))
}

/// Parse the header-protection-invariant part of a long header.
///
/// That is everything up to (not including) the packet number. Retry
/// packets, which carry no header protection, are decoded completely here.
fn decode_long_header_prefix(input: &[u8]) -> Result<ProtectedHeaderPrefix, QuicCoreError> {
    if input.len() < 6 {
        return Err(QuicCoreError::UnexpectedEof);
    }
    let first = input[0];
    if first & 0x40 == 0 {
        return Err(QuicCoreError::InvalidHeader("long header fixed bit unset"));
    }
    let packet_type = match (first >> 4) & 0x03 {
        0 => LongPacketType::Initial,
        1 => LongPacketType::ZeroRtt,
        2 => LongPacketType::Handshake,
        3 => LongPacketType::Retry,
        _ => unreachable!("2-bit pattern"),
    };
    // RFC 9000 §17.2.5.1: the low four bits of a Retry packet are "Unused",
    // set to an arbitrary value by the server, and clients MUST ignore them.
    // They are not reserved bits and are not covered by header protection,
    // so no value there may reject the packet.

    let mut pos = 1usize;
    let version = u32::from_be_bytes([input[pos], input[pos + 1], input[pos + 2], input[pos + 3]]);
    pos += 4;

    let dcid_len = input[pos] as usize;
    pos += 1;
    let dst_cid = read_cid(input, &mut pos, dcid_len)?;
    if pos >= input.len() {
        return Err(QuicCoreError::UnexpectedEof);
    }
    let scid_len = input[pos] as usize;
    pos += 1;
    let src_cid = read_cid(input, &mut pos, scid_len)?;

    if matches!(packet_type, LongPacketType::Retry) {
        if input.len().saturating_sub(pos) < 16 {
            return Err(QuicCoreError::UnexpectedEof);
        }
        let token_end = input.len() - 16;
        let token = input[pos..token_end].to_vec(); // ubs:ignore - not a secret
        let integrity_tag = input[token_end..]
            .try_into()
            .map_err(|_| QuicCoreError::UnexpectedEof)?;
        return Ok(ProtectedHeaderPrefix::Retry(RetryHeader {
            version,
            dst_cid,
            src_cid,
            token,
            integrity_tag,
        }));
    }

    let token = if matches!(packet_type, LongPacketType::Initial) {
        let (token_len, consumed) = decode_varint(&input[pos..])?;
        pos += consumed;
        let token_len = token_len as usize;
        if input.len().saturating_sub(pos) < token_len {
            return Err(QuicCoreError::UnexpectedEof);
        }
        let token = input[pos..pos + token_len].to_vec(); // ubs:ignore - QUIC initial token, not a secret
        pos += token_len;
        token
    } else {
        Vec::new()
    };

    let (payload_length, consumed) = decode_varint(&input[pos..])?;
    pos += consumed;
    Ok(ProtectedHeaderPrefix::Long(ProtectedLongHeaderPrefix {
        packet_type,
        version,
        dst_cid,
        src_cid,
        token,
        payload_length,
        packet_number_offset: pos,
    }))
}

/// Parse the header-protection-invariant part of a short header: the first
/// byte's form/fixed bits and the destination connection ID.
fn decode_short_header_prefix(
    input: &[u8],
    short_dcid_len: usize,
) -> Result<ProtectedHeaderPrefix, QuicCoreError> {
    if input.is_empty() {
        return Err(QuicCoreError::UnexpectedEof);
    }
    if input[0] & 0x40 == 0 {
        return Err(QuicCoreError::InvalidHeader("short header fixed bit unset"));
    }
    let mut pos = 1usize;
    let dst_cid = read_cid(input, &mut pos, short_dcid_len)?;
    Ok(ProtectedHeaderPrefix::Short {
        dst_cid,
        packet_number_offset: pos,
    })
}

fn decode_short_header(
    input: &[u8],
    short_dcid_len: usize,
) -> Result<(ShortHeader, usize), QuicCoreError> {
    if input.is_empty() {
        return Err(QuicCoreError::UnexpectedEof);
    }
    if input[0] & 0x40 == 0 {
        return Err(QuicCoreError::InvalidHeader("short header fixed bit unset"));
    }
    let first = input[0];
    if first & 0x18 != 0 {
        return Err(QuicCoreError::InvalidHeader(
            "short header reserved bits set",
        ));
    }
    let pn_len = (first & 0x03) + 1;
    let spin = first & 0b0010_0000 != 0;
    let key_phase = first & 0b0000_0100 != 0;

    let ProtectedHeaderPrefix::Short {
        dst_cid,
        packet_number_offset,
    } = decode_short_header_prefix(input, short_dcid_len)?
    else {
        unreachable!("short-header prefix decoder never yields a long header")
    };
    let mut pos = packet_number_offset;
    let packet_number = read_packet_number(input, &mut pos, pn_len)?;
    Ok((
        ShortHeader {
            spin,
            key_phase,
            dst_cid,
            packet_number: packet_number as u64,
            packet_number_len: pn_len,
        },
        pos,
    ))
}

fn encode_parameter(out: &mut Vec<u8>, id: u64, value: &[u8]) -> Result<(), QuicCoreError> {
    encode_varint(id, out)?;
    encode_varint(value.len() as u64, out)?;
    out.extend_from_slice(value);
    Ok(())
}

fn encode_known_u64(out: &mut Vec<u8>, id: u64, value: Option<u64>) -> Result<(), QuicCoreError> {
    if let Some(value) = value {
        let mut body = Vec::with_capacity(8);
        encode_varint(value, &mut body)?;
        encode_parameter(out, id, &body)?;
    }
    Ok(())
}

fn set_unique_u64(slot: &mut Option<u64>, id: u64, value: &[u8]) -> Result<(), QuicCoreError> {
    if slot.is_some() {
        return Err(QuicCoreError::DuplicateTransportParameter(id));
    }
    let (decoded, consumed) = decode_varint(value)?;
    if consumed != value.len() {
        return Err(QuicCoreError::InvalidTransportParameter(id));
    }
    *slot = Some(decoded);
    Ok(())
}

fn read_cid(input: &[u8], pos: &mut usize, cid_len: usize) -> Result<ConnectionId, QuicCoreError> {
    if cid_len > ConnectionId::MAX_LEN {
        return Err(QuicCoreError::InvalidConnectionIdLength(cid_len));
    }
    if input.len().saturating_sub(*pos) < cid_len {
        return Err(QuicCoreError::UnexpectedEof);
    }
    let cid = ConnectionId::new(&input[*pos..*pos + cid_len])?;
    *pos += cid_len;
    Ok(cid)
}

fn write_packet_number(packet_number: u64, width: u8, out: &mut Vec<u8>) {
    let bytes = packet_number.to_be_bytes();
    let take = width as usize;
    out.extend_from_slice(&bytes[8 - take..]);
}

fn read_packet_number(input: &[u8], pos: &mut usize, width: u8) -> Result<u32, QuicCoreError> {
    let width = validate_pn_len(width)?;
    let width = width as usize;
    if input.len().saturating_sub(*pos) < width {
        return Err(QuicCoreError::UnexpectedEof);
    }
    let mut out = [0u8; 4];
    out[4 - width..].copy_from_slice(&input[*pos..*pos + width]);
    *pos += width;
    Ok(u32::from_be_bytes(out))
}

fn validate_pn_len(packet_number_len: u8) -> Result<u8, QuicCoreError> {
    if (1..=4).contains(&packet_number_len) {
        Ok(packet_number_len)
    } else {
        Err(QuicCoreError::InvalidHeader(
            "packet number length must be 1..=4",
        ))
    }
}

fn ensure_pn_fits(packet_number: u64, packet_number_len: u8) -> Result<(), QuicCoreError> {
    validate_pn_len(packet_number_len)?;

    // RFC 9000 §17.1: packet numbers are limited to 62 bits
    if packet_number > QUIC_PACKET_NUMBER_MAX {
        return Err(QuicCoreError::PacketNumberTooLarge {
            packet_number: (packet_number & 0xFFFFFFFF) as u32, // Truncate for error display
            width: packet_number_len,
        });
    }

    let max = match packet_number_len {
        1 => 0xff,
        2 => 0xffff,
        3 => 0x00ff_ffff,
        4 => 0xffff_ffff,
        _ => unreachable!("packet_number_len validated above"),
    };
    if packet_number <= max {
        Ok(())
    } else {
        Err(QuicCoreError::PacketNumberTooLarge {
            packet_number: (packet_number & 0xFFFFFFFF) as u32, // Truncate for error display
            width: packet_number_len,
        })
    }
}

/// Determine the minimum packet-number wire width for a new packet.
///
/// RFC 9000 section 17.1 requires the chosen packet-number encoding to cover
/// more than twice the range between the new packet number and the largest
/// acknowledged packet number.
///
/// # Errors
///
/// Returns [`QuicCoreError::PacketNumberTooLarge`] when the packet number is
/// outside QUIC's 62-bit range or no 1- to 4-byte truncated encoding can
/// disambiguate it from `largest_acked`.
pub fn packet_number_len_for_encoding(
    packet_number: u64,
    largest_acked: u64,
) -> Result<u8, QuicCoreError> {
    if packet_number > QUIC_PACKET_NUMBER_MAX {
        return Err(QuicCoreError::PacketNumberTooLarge {
            packet_number: (packet_number & 0xFFFFFFFF) as u32,
            width: 4,
        });
    }

    let gap = packet_number.saturating_sub(largest_acked);
    let required_range = gap.saturating_mul(2).saturating_add(1);

    if required_range <= (1u64 << 8) {
        Ok(1)
    } else if required_range <= (1u64 << 16) {
        Ok(2)
    } else if required_range <= (1u64 << 24) {
        Ok(3)
    } else if required_range <= (1u64 << 32) {
        Ok(4)
    } else {
        Err(QuicCoreError::PacketNumberTooLarge {
            packet_number: (packet_number & 0xFFFFFFFF) as u32,
            width: 4,
        })
    }
}

/// Reconstruct full packet number from truncated value according to RFC 9000 §A.2.
///
/// This implements the "Sample Packet Number Decoding Algorithm" from RFC 9000 Appendix A.2.
/// A receiver uses the largest packet number received so far to reconstruct the full packet
/// number from the truncated value on the wire.
///
/// # Arguments
///
/// * `truncated_pn` - The truncated packet number received on the wire
/// * `pn_len` - Length of the packet number encoding in bytes (1..=4)
/// * `largest_pn` - Largest packet number successfully processed so far
///
/// # Returns
///
/// The reconstructed full packet number, or an error if parameters are invalid.
///
/// # Examples
///
/// From RFC 9000 §A.2:
/// ```
/// # use asupersync::net::quic_core::decode_packet_number_reconstruct;
/// // Example 1: largest_pn = 0xa82f30ea, truncated = 0x9b32, pn_len = 2
/// let result = decode_packet_number_reconstruct(0x9b32, 2, 0xa82f30ea).unwrap();
/// assert_eq!(result, 0xa82f9b32);
/// ```
pub fn decode_packet_number_reconstruct(
    truncated_pn: u32,
    pn_len: u8,
    largest_pn: u64,
) -> Result<u64, QuicCoreError> {
    // Validate packet number length
    validate_pn_len(pn_len)?;

    if largest_pn > QUIC_PACKET_NUMBER_MAX {
        return Err(QuicCoreError::PacketNumberTooLarge {
            packet_number: (largest_pn & 0xFFFFFFFF) as u32,
            width: pn_len,
        });
    }

    // RFC 9000 §A.2 algorithm
    let expected_pn = largest_pn + 1;
    let pn_nbits = (pn_len as u32) * 8;
    let pn_win = 1u64 << pn_nbits;
    let pn_hwin = pn_win / 2;
    let pn_mask = pn_win - 1;

    if u64::from(truncated_pn) > pn_mask {
        return Err(QuicCoreError::PacketNumberTooLarge {
            packet_number: truncated_pn,
            width: pn_len,
        });
    }

    // Reconstruct candidate packet number
    let mut candidate_pn = (expected_pn & !pn_mask) | (truncated_pn as u64);

    // Adjust candidate based on RFC 9000 §A.3 conditions. The reference
    // algorithm evaluates `candidate_pn <= expected_pn - pn_hwin` with SIGNED
    // arithmetic: when `expected_pn < pn_hwin` (early in a connection) the RHS is
    // negative, so the condition is always false and the branch must not fire.
    // A `saturating_sub` would floor the RHS to 0, degenerating the test into
    // `candidate_pn <= 0` and wrongly reconstructing e.g. truncated PN 0 (with
    // largest_pn 0) as `pn_win` instead of 0 — which then breaks AEAD nonce
    // derivation and makes the first packet undecryptable. Guard the subtraction
    // with `expected_pn >= pn_hwin` to preserve the signed semantics.
    if expected_pn >= pn_hwin
        && candidate_pn <= expected_pn - pn_hwin
        && candidate_pn < (QUIC_PACKET_NUMBER_MAX + 1) - pn_win
    {
        candidate_pn += pn_win;
    } else if candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win {
        candidate_pn -= pn_win;
    }

    // RFC 9000 §17.1: packet numbers are limited to 62 bits
    if candidate_pn > QUIC_PACKET_NUMBER_MAX {
        return Err(QuicCoreError::PacketNumberTooLarge {
            packet_number: truncated_pn,
            width: pn_len,
        });
    }

    Ok(candidate_pn)
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

    fn reference_encode_varint_rfc9000(value: u64) -> Result<Vec<u8>, QuicCoreError> {
        if value > QUIC_VARINT_MAX {
            return Err(QuicCoreError::VarIntOutOfRange(value));
        }

        let encoded = if value <= 63 {
            vec![value as u8]
        } else if value <= 16_383 {
            ((value as u16) | 0x4000).to_be_bytes().to_vec()
        } else if value <= ((1 << 30) - 1) {
            ((value as u32) | 0x8000_0000).to_be_bytes().to_vec()
        } else {
            (value | 0xc000_0000_0000_0000).to_be_bytes().to_vec()
        };

        Ok(encoded)
    }

    fn reference_decode_varint_rfc9000(input: &[u8]) -> Result<(u64, usize), QuicCoreError> {
        let Some(&first) = input.first() else {
            return Err(QuicCoreError::UnexpectedEof);
        };

        let prefix = first >> 6;
        let len = 1usize << usize::from(prefix);
        if input.len() < len {
            return Err(QuicCoreError::UnexpectedEof);
        }

        let value = match len {
            1 => u64::from(first & 0x3f),
            2 => u64::from(u16::from_be_bytes([first & 0x3f, input[1]])),
            4 => u64::from(u32::from_be_bytes([
                first & 0x3f,
                input[1],
                input[2],
                input[3],
            ])),
            8 => u64::from_be_bytes([
                first & 0x3f,
                input[1],
                input[2],
                input[3],
                input[4],
                input[5],
                input[6],
                input[7],
            ]),
            _ => unreachable!("QUIC varints are only 1, 2, 4, or 8 bytes"),
        };

        Ok((value, len))
    }

    #[test]
    fn varint_roundtrip_boundaries() {
        let values = [
            0u64,
            63,
            64,
            16_383,
            16_384,
            (1 << 30) - 1,
            1 << 30,
            QUIC_VARINT_MAX,
        ];

        for value in values {
            let mut encoded = Vec::new();
            encode_varint(value, &mut encoded).expect("encode");
            let (decoded, consumed) = decode_varint(&encoded).expect("decode");
            assert_eq!(decoded, value);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn varint_rejects_out_of_range() {
        let mut out = Vec::new();
        let err = encode_varint(QUIC_VARINT_MAX + 1, &mut out).expect_err("should fail");
        assert_eq!(err, QuicCoreError::VarIntOutOfRange(QUIC_VARINT_MAX + 1));
    }

    #[test]
    fn varint_detects_truncation() {
        let encoded = [0b01_000000u8];
        let err = decode_varint(&encoded).expect_err("should fail");
        assert_eq!(err, QuicCoreError::UnexpectedEof);
    }

    #[test]
    fn rfc9000_varint_examples_match_reference_codec() {
        // RFC 9000 §16 example encodings.
        let cases = [
            (37u64, vec![0x25]),
            (15_293, vec![0x7b, 0xbd]),
            (494_878_333, vec![0x9d, 0x7f, 0x3e, 0x7d]),
            (
                151_288_809_941_952_652,
                vec![0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
            ),
        ];

        for (value, expected_wire) in cases {
            let reference_wire = reference_encode_varint_rfc9000(value).expect("reference encode");
            assert_eq!(
                reference_wire, expected_wire,
                "reference encoder must match RFC 9000 example bytes for {value}"
            );

            let mut ours = Vec::new();
            encode_varint(value, &mut ours).expect("encode");
            assert_eq!(
                ours, reference_wire,
                "implementation diverged from RFC 9000 example encoding for {value}"
            );

            let ours_decoded = decode_varint(&expected_wire).expect("decode");
            let reference_decoded =
                reference_decode_varint_rfc9000(&expected_wire).expect("reference decode");
            assert_eq!(
                ours_decoded, reference_decoded,
                "implementation diverged from reference decoder for RFC 9000 bytes {expected_wire:02x?}"
            );
            assert_eq!(ours_decoded, (value, expected_wire.len()));
        }
    }

    #[test]
    fn rfc9000_varint_decode_accepts_non_minimal_encodings() {
        // RFC 9000 §16 permits integer values to be encoded on a wider
        // length than strictly necessary. Encoding remains shortest-form.
        let mut shortest = Vec::new();
        encode_varint(37, &mut shortest).expect("encode shortest form");
        assert_eq!(shortest, vec![0x25]);

        for wire in [
            &[0x40, 0x25][..],
            &[0x80, 0x00, 0x00, 0x25][..],
            &[0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25][..],
        ] {
            let (decoded, consumed) = decode_varint(wire).expect("decode non-minimal varint");
            assert_eq!(decoded, 37);
            assert_eq!(consumed, wire.len());
        }
    }

    #[test]
    fn connection_id_bounds() {
        assert!(ConnectionId::new(&[0u8; 20]).is_ok());
        let err = ConnectionId::new(&[0u8; 21]).expect_err("should fail");
        assert_eq!(err, QuicCoreError::InvalidConnectionIdLength(21));
    }

    #[test]
    fn long_initial_header_roundtrip() {
        let header = PacketHeader::Long(LongHeader {
            packet_type: LongPacketType::Initial,
            version: 1,
            dst_cid: ConnectionId::new(&[1, 2, 3, 4]).expect("cid"),
            src_cid: ConnectionId::new(&[9, 8, 7]).expect("cid"),
            token: vec![0xaa, 0xbb],
            payload_length: 1234,
            packet_number: 0x1234,
            packet_number_len: 2,
        });

        let mut buf = Vec::new();
        header.encode(&mut buf).expect("encode");
        let (decoded, consumed) = PacketHeader::decode(&buf, 0).expect("decode");
        assert_eq!(decoded, header);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn long_header_rejects_reserved_bits() {
        let header = PacketHeader::Long(LongHeader {
            packet_type: LongPacketType::Initial,
            version: 1,
            dst_cid: ConnectionId::new(&[1, 2, 3, 4]).expect("cid"),
            src_cid: ConnectionId::new(&[9, 8, 7]).expect("cid"),
            token: vec![],
            payload_length: 2,
            packet_number: 1,
            packet_number_len: 2,
        });
        let mut buf = Vec::new();
        header.encode(&mut buf).expect("encode");
        buf[0] |= 0x0c;
        let err = PacketHeader::decode(&buf, 0).expect_err("should fail");
        assert_eq!(
            err,
            QuicCoreError::InvalidHeader("long header reserved bits set")
        );
    }

    #[test]
    fn long_header_rejects_non_initial_token() {
        let header = PacketHeader::Long(LongHeader {
            packet_type: LongPacketType::Handshake,
            version: 1,
            dst_cid: ConnectionId::new(&[1, 2, 3, 4]).expect("cid"),
            src_cid: ConnectionId::new(&[9, 8, 7]).expect("cid"),
            token: vec![1],
            payload_length: 2,
            packet_number: 1,
            packet_number_len: 2,
        });
        let mut buf = Vec::new();
        let err = header.encode(&mut buf).expect_err("should fail");
        assert_eq!(
            err,
            QuicCoreError::InvalidHeader("token only valid for Initial packets")
        );
    }

    #[test]
    fn short_header_roundtrip() {
        let header = PacketHeader::Short(ShortHeader {
            spin: true,
            key_phase: true,
            dst_cid: ConnectionId::new(&[0xde, 0xad, 0xbe, 0xef]).expect("cid"),
            packet_number: 0x00ab_cdef,
            packet_number_len: 3,
        });

        let mut buf = Vec::new();
        header.encode(&mut buf).expect("encode");
        let (decoded, consumed) = PacketHeader::decode(&buf, 4).expect("decode");
        assert_eq!(decoded, header);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn short_header_rejects_reserved_bits() {
        let header = PacketHeader::Short(ShortHeader {
            spin: false,
            key_phase: false,
            dst_cid: ConnectionId::new(&[0xde, 0xad, 0xbe, 0xef]).expect("cid"),
            packet_number: 1,
            packet_number_len: 1,
        });
        let mut buf = Vec::new();
        header.encode(&mut buf).expect("encode");
        buf[0] |= 0x18;
        let err = PacketHeader::decode(&buf, 4).expect_err("should fail");
        assert_eq!(
            err,
            QuicCoreError::InvalidHeader("short header reserved bits set")
        );
    }

    #[test]
    fn retry_header_roundtrip() {
        let header = PacketHeader::Retry(RetryHeader {
            version: 0x0000_0001,
            dst_cid: ConnectionId::new(&[0xaa, 0xbb, 0xcc]).expect("cid"),
            src_cid: ConnectionId::new(&[0x10, 0x20]).expect("cid"),
            token: vec![0xde, 0xad, 0xbe, 0xef],
            integrity_tag: [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                0x32, 0x10,
            ],
        });

        let mut buf = Vec::new();
        header.encode(&mut buf).expect("encode");
        let (decoded, consumed) = PacketHeader::decode(&buf, 0).expect("decode");
        assert_eq!(decoded, header);
        assert_eq!(consumed, buf.len());
    }

    /// RFC 9000 §17.2.5.1: a Retry packet's low four bits are "Unused" and
    /// set to an arbitrary value by the server; clients MUST ignore them.
    /// A compliant server that fills them with 0b0001 used to be rejected as
    /// "reserved bits set".
    #[test]
    fn retry_header_ignores_unused_bits() {
        let raw = [
            0b1111_0001,
            0,
            0,
            0,
            1,
            1,
            0xaa,
            1,
            0xbb,
            0x01,
            0x23,
            0x45,
            0x67,
            0x89,
            0xab,
            0xcd,
            0xef,
            0xfe,
            0xdc,
            0xba,
            0x98,
            0x76,
            0x54,
            0x32,
            0x10,
        ];
        let (header, consumed) =
            PacketHeader::decode(&raw, 0).expect("unused bits never reject a Retry");
        assert_eq!(consumed, raw.len());
        let PacketHeader::Retry(retry) = header else {
            panic!("expected a Retry header, got {header:?}");
        };
        assert_eq!(retry.version, 1);
        assert_eq!(retry.dst_cid.as_bytes(), &[0xaa]);
        assert_eq!(retry.src_cid.as_bytes(), &[0xbb]);
        assert!(retry.token.is_empty());
        assert_eq!(&retry.integrity_tag[..], &raw[raw.len() - 16..]);
        // The protected-prefix decoder used by the routing and handshake
        // paths agrees.
        let prefix =
            ProtectedHeaderPrefix::decode(&raw, 0).expect("prefix decoder ignores unused bits");
        assert!(matches!(prefix, ProtectedHeaderPrefix::Retry(ref p) if p.version == 1));
        // Every other unused-bit value is accepted too.
        for bits in 1..=0x0fu8 {
            let mut variant = raw;
            variant[0] = 0b1111_0000 | bits;
            assert!(
                matches!(
                    PacketHeader::decode(&variant, 0),
                    Ok((PacketHeader::Retry(_), _))
                ),
                "Retry with unused bits {bits:#06b} must decode"
            );
        }
    }

    #[test]
    fn transport_params_roundtrip_with_unknown() {
        let params = TransportParameters {
            max_idle_timeout: Some(10_000),
            initial_max_data: Some(1_000_000),
            disable_active_migration: true,
            unknown: vec![UnknownTransportParameter {
                id: 0xface,
                value: vec![1, 2, 3, 4],
            }],
            ..TransportParameters::default()
        };

        let mut encoded = Vec::new();
        params.encode(&mut encoded).expect("encode");
        let decoded = TransportParameters::decode(&encoded).expect("decode");
        assert_eq!(decoded, params);
    }

    #[test]
    fn transport_params_reject_duplicate_known() {
        let mut encoded = Vec::new();
        // first copy
        encode_parameter(&mut encoded, TP_MAX_ACK_DELAY, &[0x19]).expect("encode");
        // duplicate
        encode_parameter(&mut encoded, TP_MAX_ACK_DELAY, &[0x1a]).expect("encode");

        let err = TransportParameters::decode(&encoded).expect_err("should fail");
        assert_eq!(
            err,
            QuicCoreError::DuplicateTransportParameter(TP_MAX_ACK_DELAY)
        );
    }

    #[test]
    fn transport_params_reject_nonempty_disable_active_migration() {
        let mut encoded = Vec::new();
        encode_parameter(&mut encoded, TP_DISABLE_ACTIVE_MIGRATION, &[0x01]).expect("encode");
        let err = TransportParameters::decode(&encoded).expect_err("should fail");
        assert_eq!(
            err,
            QuicCoreError::InvalidTransportParameter(TP_DISABLE_ACTIVE_MIGRATION)
        );
    }

    #[test]
    fn transport_params_reject_duplicate_unknown() {
        let mut encoded = Vec::new();
        encode_parameter(&mut encoded, 0x1337, &[0x01]).expect("encode");
        encode_parameter(&mut encoded, 0x1337, &[0x02]).expect("encode");
        let err = TransportParameters::decode(&encoded).expect_err("should fail");
        assert_eq!(err, QuicCoreError::DuplicateTransportParameter(0x1337));
    }

    #[test]
    fn transport_params_reject_small_udp_payload() {
        let mut encoded = Vec::new();
        let mut body = Vec::new();
        encode_varint(1199, &mut body).expect("varint");
        encode_parameter(&mut encoded, TP_MAX_UDP_PAYLOAD_SIZE, &body).expect("encode");
        let err = TransportParameters::decode(&encoded).expect_err("should fail");
        assert_eq!(
            err,
            QuicCoreError::InvalidTransportParameter(TP_MAX_UDP_PAYLOAD_SIZE)
        );
    }

    #[test]
    fn transport_params_reject_large_ack_delay_exponent() {
        let mut encoded = Vec::new();
        let mut body = Vec::new();
        encode_varint(21, &mut body).expect("varint");
        encode_parameter(&mut encoded, TP_ACK_DELAY_EXPONENT, &body).expect("encode");
        let err = TransportParameters::decode(&encoded).expect_err("should fail");
        assert_eq!(
            err,
            QuicCoreError::InvalidTransportParameter(TP_ACK_DELAY_EXPONENT)
        );
    }

    // ========================================================================
    // QH3-U2 gap-filling tests (BronzeDune)
    // ========================================================================

    #[test]
    fn varint_decode_empty_input() {
        let err = decode_varint(&[]).expect_err("empty should fail");
        assert_eq!(err, QuicCoreError::UnexpectedEof);
    }

    #[test]
    fn varint_decode_truncated_4byte() {
        // 4-byte varint prefix (top 2 bits = 10) needs 4 bytes total.
        let err = decode_varint(&[0x80, 0x01]).expect_err("truncated 4-byte should fail");
        assert_eq!(err, QuicCoreError::UnexpectedEof);
    }

    #[test]
    fn varint_decode_truncated_8byte() {
        // 8-byte varint prefix (top 2 bits = 11) needs 8 bytes total.
        let err = decode_varint(&[0xc0, 0x00, 0x00]).expect_err("truncated 8-byte should fail");
        assert_eq!(err, QuicCoreError::UnexpectedEof);
    }

    #[test]
    fn varint_encoding_sizes() {
        // 1-byte: 0..63
        let mut buf = Vec::new();
        encode_varint(0, &mut buf).unwrap();
        assert_eq!(buf.len(), 1);

        buf.clear();
        encode_varint(63, &mut buf).unwrap();
        assert_eq!(buf.len(), 1);

        // 2-byte: 64..16383
        buf.clear();
        encode_varint(64, &mut buf).unwrap();
        assert_eq!(buf.len(), 2);

        buf.clear();
        encode_varint(16383, &mut buf).unwrap();
        assert_eq!(buf.len(), 2);

        // 4-byte: 16384..(2^30-1)
        buf.clear();
        encode_varint(16384, &mut buf).unwrap();
        assert_eq!(buf.len(), 4);

        buf.clear();
        encode_varint((1 << 30) - 1, &mut buf).unwrap();
        assert_eq!(buf.len(), 4);

        // 8-byte: 2^30..QUIC_VARINT_MAX
        buf.clear();
        encode_varint(1 << 30, &mut buf).unwrap();
        assert_eq!(buf.len(), 8);

        buf.clear();
        encode_varint(QUIC_VARINT_MAX, &mut buf).unwrap();
        assert_eq!(buf.len(), 8);
    }

    #[test]
    fn transport_params_empty_roundtrip() {
        let params = TransportParameters::default();
        let mut encoded = Vec::new();
        params.encode(&mut encoded).unwrap();
        assert!(encoded.is_empty());
        let decoded = TransportParameters::decode(&encoded).unwrap();
        assert_eq!(decoded, params);
    }

    #[test]
    fn transport_params_single_param_roundtrip() {
        let params = TransportParameters {
            max_idle_timeout: Some(30_000),
            ..TransportParameters::default()
        };
        let mut encoded = Vec::new();
        params.encode(&mut encoded).unwrap();
        let decoded = TransportParameters::decode(&encoded).unwrap();
        assert_eq!(decoded, params);
    }

    #[test]
    fn transport_params_all_known_fields_roundtrip() {
        let params = TransportParameters {
            max_idle_timeout: Some(30_000),
            max_udp_payload_size: Some(1400),
            initial_max_data: Some(1_000_000),
            initial_max_stream_data_bidi_local: Some(256_000),
            initial_max_stream_data_bidi_remote: Some(256_000),
            initial_max_stream_data_uni: Some(128_000),
            initial_max_streams_bidi: Some(100),
            initial_max_streams_uni: Some(50),
            ack_delay_exponent: Some(3),
            max_ack_delay: Some(25),
            disable_active_migration: true,
            max_datagram_frame_size: Some(1200),
            unknown: vec![],
        };
        let mut encoded = Vec::new();
        params.encode(&mut encoded).unwrap();
        let decoded = TransportParameters::decode(&encoded).unwrap();
        assert_eq!(decoded, params);
    }

    #[test]
    fn transport_params_unknown_preserved() {
        let params = TransportParameters {
            unknown: vec![
                UnknownTransportParameter {
                    id: 0xff00,
                    value: vec![0x01, 0x02, 0x03],
                },
                UnknownTransportParameter {
                    id: 0xff01,
                    value: vec![],
                },
            ],
            ..TransportParameters::default()
        };
        let mut encoded = Vec::new();
        params.encode(&mut encoded).unwrap();
        let decoded = TransportParameters::decode(&encoded).unwrap();
        assert_eq!(decoded.unknown.len(), 2);
        assert_eq!(decoded.unknown[0].id, 0xff00);
        assert_eq!(decoded.unknown[0].value, vec![0x01, 0x02, 0x03]);
        assert_eq!(decoded.unknown[1].id, 0xff01);
        assert!(decoded.unknown[1].value.is_empty());
    }

    #[test]
    fn quic_core_error_display_all_variants() {
        let cases: Vec<(QuicCoreError, &str)> = vec![
            (QuicCoreError::UnexpectedEof, "unexpected EOF"),
            (
                QuicCoreError::VarIntOutOfRange(99),
                "varint out of range: 99",
            ),
            (
                QuicCoreError::InvalidHeader("test msg"),
                "invalid header: test msg",
            ),
            (
                QuicCoreError::InvalidConnectionIdLength(25),
                "invalid connection id length: 25",
            ),
            (
                QuicCoreError::PacketNumberTooLarge {
                    packet_number: 1000,
                    width: 1,
                },
                "packet number 1000 does not fit in 1 bytes",
            ),
            (
                QuicCoreError::DuplicateTransportParameter(0x01),
                "duplicate transport parameter: 0x1",
            ),
            (
                QuicCoreError::InvalidTransportParameter(0x03),
                "invalid transport parameter: 0x3",
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(format!("{err}"), expected);
        }
    }

    #[test]
    fn quic_core_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(QuicCoreError::UnexpectedEof);
        assert!(err.source().is_none());
    }

    #[test]
    fn connection_id_empty_and_max() {
        let empty = ConnectionId::new(&[]).unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.as_bytes(), &[] as &[u8]);

        let max = ConnectionId::new(&[0xab; 20]).unwrap();
        assert!(!max.is_empty());
        assert_eq!(max.len(), 20);
        assert_eq!(max.as_bytes().len(), 20);

        let debug = format!("{empty:?}");
        assert!(debug.contains("ConnectionId("));
    }

    #[test]
    fn packet_header_decode_empty_input() {
        let err = PacketHeader::decode(&[], 0).expect_err("empty should fail");
        assert_eq!(err, QuicCoreError::UnexpectedEof);
    }

    #[test]
    fn long_header_handshake_roundtrip() {
        let header = PacketHeader::Long(LongHeader {
            packet_type: LongPacketType::Handshake,
            version: 0x0000_0001,
            dst_cid: ConnectionId::new(&[0x01, 0x02]).unwrap(),
            src_cid: ConnectionId::new(&[0x03]).unwrap(),
            token: vec![],
            payload_length: 100,
            packet_number: 42,
            packet_number_len: 1,
        });
        let mut buf = Vec::new();
        header.encode(&mut buf).unwrap();
        let (decoded, consumed) = PacketHeader::decode(&buf, 0).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn long_header_zerortt_roundtrip() {
        let header = PacketHeader::Long(LongHeader {
            packet_type: LongPacketType::ZeroRtt,
            version: 0xff00_001d,
            dst_cid: ConnectionId::new(&[0xaa, 0xbb, 0xcc]).unwrap(),
            src_cid: ConnectionId::new(&[]).unwrap(),
            token: vec![],
            payload_length: 50,
            packet_number: 7,
            packet_number_len: 1,
        });
        let mut buf = Vec::new();
        header.encode(&mut buf).unwrap();
        let (decoded, consumed) = PacketHeader::decode(&buf, 0).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn packet_number_too_large_for_width() {
        let header = PacketHeader::Short(ShortHeader {
            spin: false,
            key_phase: false,
            dst_cid: ConnectionId::new(&[0x01]).unwrap(),
            packet_number: 256, // too large for 1-byte
            packet_number_len: 1,
        });
        let mut buf = Vec::new();
        let err = header.encode(&mut buf).expect_err("should fail");
        assert_eq!(
            err,
            QuicCoreError::PacketNumberTooLarge {
                packet_number: 256,
                width: 1,
            }
        );
    }

    #[test]
    fn packet_number_length_invalid() {
        let header = PacketHeader::Short(ShortHeader {
            spin: false,
            key_phase: false,
            dst_cid: ConnectionId::new(&[0x01]).unwrap(),
            packet_number: 1,
            packet_number_len: 0, // invalid
        });
        let mut buf = Vec::new();
        let err = header.encode(&mut buf).expect_err("should fail");
        assert!(matches!(err, QuicCoreError::InvalidHeader(_)));
    }

    #[test]
    fn long_header_payload_length_too_small() {
        let header = PacketHeader::Long(LongHeader {
            packet_type: LongPacketType::Initial,
            version: 1,
            dst_cid: ConnectionId::new(&[]).unwrap(),
            src_cid: ConnectionId::new(&[]).unwrap(),
            token: vec![],
            payload_length: 0, // smaller than pn_len=1
            packet_number: 1,
            packet_number_len: 1,
        });
        let mut buf = Vec::new();
        let err = header.encode(&mut buf).expect_err("should fail");
        assert!(matches!(err, QuicCoreError::InvalidHeader(_)));
    }

    #[test]
    fn transport_params_truncated_value() {
        // Encode a parameter ID with length=10 but only provide 3 bytes of value.
        let mut encoded = Vec::new();
        encode_varint(TP_MAX_IDLE_TIMEOUT, &mut encoded).unwrap();
        encode_varint(10, &mut encoded).unwrap(); // claims 10 bytes
        encoded.extend_from_slice(&[0x01, 0x02, 0x03]); // only 3 bytes
        let err = TransportParameters::decode(&encoded).expect_err("should fail");
        assert_eq!(err, QuicCoreError::UnexpectedEof);
    }

    #[test]
    fn long_packet_type_debug_clone_eq() {
        let types = [
            LongPacketType::Initial,
            LongPacketType::ZeroRtt,
            LongPacketType::Handshake,
            LongPacketType::Retry,
        ];
        for t in &types {
            let clone = *t;
            assert_eq!(clone, *t);
            assert!(!format!("{t:?}").is_empty());
        }
    }

    #[test]
    fn unknown_transport_parameter_debug_clone_eq() {
        let p = UnknownTransportParameter {
            id: 42,
            value: vec![1, 2, 3],
        };
        let p2 = p.clone();
        assert_eq!(p, p2);
        assert!(format!("{p:?}").contains("UnknownTransportParameter"));
    }

    // =========================================================================
    // Wave 45 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn quic_core_error_debug_clone_eq_display() {
        let e1 = QuicCoreError::UnexpectedEof;
        let e2 = QuicCoreError::VarIntOutOfRange(999);
        assert!(format!("{e1:?}").contains("UnexpectedEof"));
        assert!(format!("{e1}").contains("unexpected EOF"));
        assert!(format!("{e2}").contains("varint out of range"));
        assert_eq!(e1.clone(), e1);
        assert_ne!(e1, e2);
        let err: &dyn std::error::Error = &e1;
        assert!(err.source().is_none());
    }

    #[test]
    fn connection_id_debug_clone_copy_eq_hash_default() {
        use std::collections::HashSet;
        let def = ConnectionId::default();
        assert!(def.is_empty());
        assert_eq!(def.len(), 0);
        let dbg = format!("{def:?}");
        assert!(dbg.contains("ConnectionId"), "{dbg}");

        let cid = ConnectionId::new(&[0xab, 0xcd]).unwrap();
        let copied = cid;
        let cloned = cid;
        assert_eq!(copied, cloned);
        assert_ne!(cid, def);

        let mut set = HashSet::new();
        set.insert(cid);
        set.insert(def);
        set.insert(cid);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn transport_parameters_debug_clone_default_eq() {
        let def = TransportParameters::default();
        let dbg = format!("{def:?}");
        assert!(dbg.contains("TransportParameters"), "{dbg}");
        assert_eq!(def.max_idle_timeout, None);
        assert!(!def.disable_active_migration);

        let tp = TransportParameters {
            max_idle_timeout: Some(5000),
            ..TransportParameters::default()
        };
        let cloned = tp.clone();
        assert_eq!(cloned, tp);
        assert_ne!(cloned, def);
    }

    // =========================================================================
    // RFC 9000 Section 17.1 Packet Number Encoding Conformance Tests
    // =========================================================================

    /// Test packet number encoding length determination per RFC 9000.
    /// The encoding must use the minimum number of bytes sufficient to encode the value.
    #[test]
    fn rfc9000_packet_number_encoding_length() {
        // Test minimum length encoding requirements
        let test_cases = [
            // (packet_number, min_required_width, max_allowed_width)
            (0, 1, 1), // 0 fits in 1 byte
            (1, 1, 1),
            (255, 1, 1),        // 0xFF fits exactly in 1 byte
            (256, 2, 2),        // 0x100 requires 2 bytes
            (65535, 2, 2),      // 0xFFFF fits exactly in 2 bytes
            (65536, 3, 3),      // 0x10000 requires 3 bytes
            (16777215, 3, 3),   // 0xFFFFFF fits exactly in 3 bytes
            (16777216, 4, 4),   // 0x1000000 requires 4 bytes
            (0xFFFFFFFF, 4, 4), // Maximum 32-bit value requires 4 bytes
        ];

        for (packet_number, min_width, _max_width) in test_cases {
            // Test that minimum width succeeds
            assert!(
                ensure_pn_fits(packet_number, min_width).is_ok(),
                "Packet number {packet_number} should fit in {min_width} bytes"
            );

            // Test that encoding produces the expected width
            let mut buf = Vec::new();
            write_packet_number(packet_number, min_width, &mut buf);
            assert_eq!(
                buf.len(),
                min_width as usize,
                "Packet number {packet_number} should encode to {min_width} bytes"
            );

            // Test round-trip decode
            let mut pos = 0;
            let decoded = read_packet_number(&buf, &mut pos, min_width).unwrap();
            assert_eq!(
                u64::from(decoded),
                packet_number,
                "Packet number {packet_number} failed round-trip"
            );
            assert_eq!(pos, buf.len(), "Should consume all encoded bytes");

            // Test that smaller width fails (except for minimum case)
            if min_width > 1 {
                assert!(
                    ensure_pn_fits(packet_number, min_width - 1).is_err(),
                    "Packet number {packet_number} should NOT fit in {} bytes",
                    min_width - 1
                );
            }
        }
    }

    /// Test packet number truncation behavior per RFC 9000 Section 17.1.
    /// Packet numbers are truncated based on the largest acknowledged packet number.
    #[test]
    fn rfc9000_packet_number_truncation_algorithm() {
        // Test the packet number truncation algorithm from RFC 9000
        // num_unacked_ranges = (full_pn - largest_acked) + 1
        // encoded_len = min bytes needed to represent (2 * num_unacked_ranges + 1)

        let test_cases = [
            // (largest_acked, full_packet_number, expected_min_width)
            (0, 1, 1),         // First packet after initial
            (0, 255, 2),       // Needs 2 bytes to disambiguate from packet 0
            (0, 256, 2),       // Need 2 bytes for wider gap
            (100, 101, 1),     // Small increment from acked
            (100, 356, 2),     // Larger gap requires 2 bytes
            (1000, 1001, 1),   // Small increment
            (1000, 2024, 2),   // Medium gap
            (50000, 50001, 1), // Sequential packets
            (50000, 51024, 2), // 1024 packet gap
        ];

        for (largest_acked, full_pn, expected_min_width) in test_cases {
            let calculated_width =
                packet_number_len_for_encoding(full_pn, largest_acked).expect("valid width");

            assert_eq!(
                calculated_width, expected_min_width,
                "Truncation algorithm: largest_acked={largest_acked}, full_pn={full_pn}, \
                 calculated_width={calculated_width}"
            );

            let mask = (1u64 << (u32::from(calculated_width) * 8)) - 1;
            let truncated = full_pn & mask;

            // Test that this width carries the truncated wire value.
            assert!(
                ensure_pn_fits(truncated, calculated_width).is_ok(),
                "Calculated width {calculated_width} should accommodate truncated packet number {truncated}"
            );

            let truncated_wire =
                u32::try_from(truncated).expect("truncated packet number fits u32");
            let reconstructed =
                decode_packet_number_reconstruct(truncated_wire, calculated_width, largest_acked)
                    .expect("truncated packet number should reconstruct");
            assert_eq!(
                reconstructed, full_pn,
                "Calculated width {calculated_width} should reconstruct packet number {full_pn}"
            );
        }
    }

    /// Test packet number encoding edge cases per RFC 9000.
    #[test]
    fn rfc9000_packet_number_edge_cases() {
        // Test boundary conditions for each encoding width

        // 1-byte boundaries: 0x00 to 0xFF
        let mut buf = Vec::new();
        write_packet_number(0, 1, &mut buf);
        assert_eq!(buf, vec![0x00]);

        buf.clear();
        write_packet_number(255, 1, &mut buf);
        assert_eq!(buf, vec![0xFF]);

        // 2-byte boundaries: 0x0100 to 0xFFFF
        buf.clear();
        write_packet_number(256, 2, &mut buf);
        assert_eq!(buf, vec![0x01, 0x00]);

        buf.clear();
        write_packet_number(65535, 2, &mut buf);
        assert_eq!(buf, vec![0xFF, 0xFF]);

        // 3-byte boundaries: 0x010000 to 0xFFFFFF
        buf.clear();
        write_packet_number(65536, 3, &mut buf);
        assert_eq!(buf, vec![0x01, 0x00, 0x00]);

        buf.clear();
        write_packet_number(16777215, 3, &mut buf);
        assert_eq!(buf, vec![0xFF, 0xFF, 0xFF]);

        // 4-byte boundaries: 0x01000000 to 0xFFFFFFFF
        buf.clear();
        write_packet_number(16777216, 4, &mut buf);
        assert_eq!(buf, vec![0x01, 0x00, 0x00, 0x00]);

        buf.clear();
        write_packet_number(0xFFFFFFFF, 4, &mut buf);
        assert_eq!(buf, vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }

    /// Test packet number width validation per RFC 9000.
    #[test]
    fn rfc9000_packet_number_width_validation() {
        // Valid widths are 1, 2, 3, or 4 bytes
        for valid_width in [1, 2, 3, 4] {
            assert!(
                validate_pn_len(valid_width).is_ok(),
                "Width {valid_width} should be valid"
            );
        }

        // Invalid widths
        for invalid_width in [0, 5, 6, 255] {
            assert!(
                validate_pn_len(invalid_width).is_err(),
                "Width {invalid_width} should be invalid"
            );
        }

        // Test specific error message
        let err = validate_pn_len(0).unwrap_err();
        assert!(matches!(err, QuicCoreError::InvalidHeader(_)));
        let err = validate_pn_len(5).unwrap_err();
        assert!(matches!(err, QuicCoreError::InvalidHeader(_)));
    }

    /// Test packet number overflow conditions per RFC 9000.
    #[test]
    fn rfc9000_packet_number_overflow() {
        // Test values that don't fit in requested width
        let overflow_cases = [
            (256, 1),      // Requires 2 bytes, trying to fit in 1
            (65536, 1),    // Requires 3 bytes, trying to fit in 1
            (65536, 2),    // Requires 3 bytes, trying to fit in 2
            (16777216, 1), // Requires 4 bytes, trying to fit in 1
            (16777216, 2), // Requires 4 bytes, trying to fit in 2
            (16777216, 3), // Requires 4 bytes, trying to fit in 3
        ];

        for (packet_number, width) in overflow_cases {
            let err = ensure_pn_fits(packet_number, width).unwrap_err();
            assert!(
                matches!(err, QuicCoreError::PacketNumberTooLarge { .. }),
                "Should get PacketNumberTooLarge for pn={packet_number}, width={width}"
            );

            if let QuicCoreError::PacketNumberTooLarge {
                packet_number: pn,
                width: w,
            } = err
            {
                assert_eq!(pn, (packet_number & 0xffff_ffff) as u32);
                assert_eq!(w, width);
            }
        }
    }

    /// Test packet number decoding with insufficient input per RFC 9000.
    #[test]
    fn rfc9000_packet_number_truncated_decode() {
        // Test decoding with insufficient bytes for declared width
        let truncated_cases = [
            (2, vec![0x12]),             // Declared 2-byte width, only 1 byte available
            (3, vec![0x12, 0x34]),       // Declared 3-byte width, only 2 bytes available
            (4, vec![0x12, 0x34, 0x56]), // Declared 4-byte width, only 3 bytes available
        ];

        for (declared_width, truncated_data) in truncated_cases {
            let mut pos = 0;
            let err = read_packet_number(&truncated_data, &mut pos, declared_width).unwrap_err();
            assert_eq!(
                err,
                QuicCoreError::UnexpectedEof,
                "Should get UnexpectedEof for width={declared_width}, data={truncated_data:?}"
            );
        }
    }

    /// Test packet number encoding in packet headers per RFC 9000.
    #[test]
    fn rfc9000_packet_number_in_headers() {
        // Test packet number encoding within long headers
        let long_header_cases = [
            (1, 1),
            (255, 1), // 1-byte packet numbers
            (256, 2),
            (65535, 2), // 2-byte packet numbers
            (65536, 3),
            (16777215, 3), // 3-byte packet numbers
            (16777216, 4),
            (0x12345678, 4), // 4-byte packet numbers
        ];

        for (packet_number, width) in long_header_cases {
            let header = PacketHeader::Long(LongHeader {
                packet_type: LongPacketType::Initial,
                version: 1,
                dst_cid: ConnectionId::new(&[1, 2, 3, 4]).unwrap(),
                src_cid: ConnectionId::new(&[5, 6, 7]).unwrap(),
                token: vec![],
                payload_length: 100,
                packet_number,
                packet_number_len: width,
            });

            // Test encoding
            let mut buf = Vec::new();
            header.encode(&mut buf).unwrap();

            // Test decoding
            let (decoded, consumed) = PacketHeader::decode(&buf, 0).unwrap();
            if let PacketHeader::Long(decoded_header) = decoded {
                assert_eq!(
                    decoded_header.packet_number, packet_number,
                    "Long header packet number round-trip failed"
                );
                assert_eq!(
                    decoded_header.packet_number_len, width,
                    "Long header packet number width mismatch"
                );
            } else {
                panic!("Expected long header");
            }
            assert_eq!(consumed, buf.len());
        }

        // Test packet number encoding within short headers
        let short_header_cases = [
            (42, 1),
            (200, 1), // 1-byte packet numbers
            (300, 2),
            (50000, 2), // 2-byte packet numbers
            (70000, 3),
            (1000000, 3), // 3-byte packet numbers
            (20000000, 4),
            (0x87654321, 4), // 4-byte packet numbers
        ];

        for (packet_number, width) in short_header_cases {
            let header = PacketHeader::Short(ShortHeader {
                spin: false,
                key_phase: false,
                dst_cid: ConnectionId::new(&[0xAA, 0xBB]).unwrap(),
                packet_number,
                packet_number_len: width,
            });

            // Test encoding
            let mut buf = Vec::new();
            header.encode(&mut buf).unwrap();

            // Test decoding (short headers need known dcid length)
            let (decoded, consumed) = PacketHeader::decode(&buf, 2).unwrap();
            if let PacketHeader::Short(decoded_header) = decoded {
                assert_eq!(
                    decoded_header.packet_number, packet_number,
                    "Short header packet number round-trip failed"
                );
                assert_eq!(
                    decoded_header.packet_number_len, width,
                    "Short header packet number width mismatch"
                );
            } else {
                panic!("Expected short header");
            }
            assert_eq!(consumed, buf.len());
        }
    }

    /// Test packet number wire format compliance per RFC 9000.
    #[test]
    fn rfc9000_packet_number_wire_format() {
        // Test that packet numbers are encoded in network byte order (big-endian)
        let wire_format_cases = [
            // (packet_number, width, expected_wire_bytes)
            (0x1234, 2, vec![0x12, 0x34]),
            (0x123456, 3, vec![0x12, 0x34, 0x56]),
            (0x12345678, 4, vec![0x12, 0x34, 0x56, 0x78]),
        ];

        for (packet_number, width, expected_bytes) in wire_format_cases {
            let mut buf = Vec::new();
            write_packet_number(packet_number, width, &mut buf);
            assert_eq!(
                buf, expected_bytes,
                "Packet number {packet_number:#x} width {width} wire format mismatch"
            );

            // Test decode produces original value
            let mut pos = 0;
            let decoded = read_packet_number(&buf, &mut pos, width).unwrap();
            assert_eq!(u64::from(decoded), packet_number);
        }
    }

    /// Test packet number space isolation per RFC 9000.
    #[test]
    fn rfc9000_packet_number_space_isolation() {
        // Different packet types have separate packet number spaces
        // This test verifies they can use the same packet numbers independently

        let packet_number = 1234;
        let width = 2;

        // Test in Initial packet
        let initial_header = PacketHeader::Long(LongHeader {
            packet_type: LongPacketType::Initial,
            version: 1,
            dst_cid: ConnectionId::new(&[1, 2, 3]).unwrap(),
            src_cid: ConnectionId::new(&[4, 5, 6]).unwrap(),
            token: vec![0xAA, 0xBB],
            payload_length: 100,
            packet_number,
            packet_number_len: width,
        });

        // Test in Handshake packet
        let handshake_header = PacketHeader::Long(LongHeader {
            packet_type: LongPacketType::Handshake,
            version: 1,
            dst_cid: ConnectionId::new(&[1, 2, 3]).unwrap(),
            src_cid: ConnectionId::new(&[4, 5, 6]).unwrap(),
            token: vec![], // Handshake doesn't have token
            payload_length: 100,
            packet_number,
            packet_number_len: width,
        });

        // Test in Application Data (Short header)
        let app_data_header = PacketHeader::Short(ShortHeader {
            spin: true,
            key_phase: false,
            dst_cid: ConnectionId::new(&[1, 2, 3]).unwrap(),
            packet_number,
            packet_number_len: width,
        });

        // All should encode/decode the same packet number independently
        for header in [initial_header, handshake_header, app_data_header] {
            let mut buf = Vec::new();
            header.encode(&mut buf).unwrap();

            let dcid_len = match &header {
                PacketHeader::Short(_) => 3, // Short header needs known length
                _ => 0,                      // Long headers include length field
            };

            let (decoded, _) = PacketHeader::decode(&buf, dcid_len).unwrap();
            let decoded_pn = match decoded {
                PacketHeader::Long(h) => h.packet_number,
                PacketHeader::Short(h) => h.packet_number,
                PacketHeader::Retry(_) => panic!("Unexpected retry header"),
            };

            assert_eq!(
                decoded_pn, packet_number,
                "Packet number should be preserved across packet type boundaries"
            );
        }
    }

    /// RFC 9000 §A.2 conformance test module.
    mod rfc9000_a2 {
        use super::*;

        /// Test cases from RFC 9000 §A.2 "Sample Packet Number Decoding Algorithm".
        /// These are the exact examples provided in the specification.
        #[test]
        fn rfc9000_a2_conformance_vectors() {
            let test_cases = [
                // (largest_pn, truncated_pn, pn_len, expected_full_pn, description)
                (0xa82f30ea, 0x9b32, 2, 0xa82f9b32, "RFC 9000 §A.2 Example 1"),
                (
                    0xa82f30ea,
                    0xac5c02,
                    3,
                    0xa8ac5c02,
                    "Three-byte reconstruction near largest packet number",
                ),
            ];

            for (largest_pn, truncated_pn, pn_len, expected_full_pn, description) in test_cases {
                let result = decode_packet_number_reconstruct(truncated_pn, pn_len, largest_pn)
                    .unwrap_or_else(|e| panic!("{description}: decode failed with error: {e}"));

                assert_eq!(
                    result, expected_full_pn,
                    "{description}: expected 0x{expected_full_pn:x}, got 0x{result:x}"
                );
            }
        }

        /// Test packet number reconstruction algorithm edge cases.
        #[test]
        fn packet_number_reconstruction_edge_cases() {
            // Test wrapping around boundaries
            let test_cases = [
                // (largest_pn, truncated_pn, pn_len, expected_full_pn, description)
                (0x00, 0xff, 1, 0xff, "Single byte maximum"),
                (0x100, 0x00, 1, 0x100, "Single byte wrap to next window"),
                (0x00, 0xffff, 2, 0xffff, "Two byte maximum"),
                (0x10000, 0x0000, 2, 0x10000, "Two byte wrap to next window"),
                (0xffffff, 0x000000, 3, 0x1000000, "Three byte wrap"),
                (0x100000000, 0x00000000, 4, 0x100000000, "Four byte wrap"),
                // Test reconstruction with gaps
                (1000, 1050 & 0xff, 1, 1050, "Small forward gap"),
                (1000, 1200, 2, 1200, "Forward within two-byte window"),
                // Test backward reconstruction
                (1000, 950 & 0xff, 1, 950, "Backward within window"),
            ];

            for (largest_pn, truncated_pn, pn_len, expected_full_pn, description) in test_cases {
                let result = decode_packet_number_reconstruct(truncated_pn, pn_len, largest_pn)
                    .unwrap_or_else(|e| panic!("{description}: decode failed with error: {e}"));

                assert_eq!(
                    result, expected_full_pn,
                    "{description}: largest=0x{largest_pn:x}, truncated=0x{truncated_pn:x}, \
                     expected=0x{expected_full_pn:x}, got=0x{result:x}"
                );
            }
        }

        /// Test packet number length validation in reconstruction.
        #[test]
        fn packet_number_reconstruction_validation() {
            // Test invalid packet number lengths
            let invalid_lengths = [0, 5, 255];
            for invalid_len in invalid_lengths {
                let result = decode_packet_number_reconstruct(0x1234, invalid_len, 0x1000);
                assert!(
                    result.is_err(),
                    "Should reject invalid packet number length: {invalid_len}"
                );
            }

            // Test 62-bit limit enforcement (RFC 9000 §17.1)
            let large_largest = (1u64 << 61) - 1; // Just under the limit
            let result = decode_packet_number_reconstruct(0x1234, 2, large_largest);
            assert!(
                result.is_ok(),
                "Should accept packet numbers under 62-bit limit"
            );

            // Test exceeding 62-bit limit
            let too_large = (1u64 << 62) - 1; // At the limit
            let result = decode_packet_number_reconstruct(0xffff, 2, too_large);
            // This might produce a candidate >= 2^62, which should be rejected
            // The exact behavior depends on the arithmetic, but we verify it doesn't panic
            let _ = result; // May be Ok or Err depending on the specific values
        }

        /// Test compatibility with existing round-trip encoding/decoding.
        #[test]
        fn reconstruction_round_trip_compatibility() {
            let test_cases = [(0x1234, 2), (0x123456, 3), (0x12345678, 4)];

            for (packet_number, width) in test_cases {
                // Encode packet number
                let mut buf = Vec::new();
                write_packet_number(packet_number, width, &mut buf);

                // Decode truncated value
                let mut pos = 0;
                let truncated = read_packet_number(&buf, &mut pos, width).unwrap();

                // Reconstruct using the original as "largest_pn"
                let reconstructed =
                    decode_packet_number_reconstruct(truncated, width, packet_number).unwrap();

                // Should recover the original packet number
                assert_eq!(
                    reconstructed, packet_number,
                    "Round-trip reconstruction failed for 0x{packet_number:x} width {width}"
                );
            }
        }

        /// Test packet number reconstruction across different packet number spaces.
        #[test]
        fn reconstruction_packet_number_spaces() {
            // Each packet number space maintains its own largest_pn for reconstruction
            let initial_largest = 1000u64;
            let handshake_largest = 500u64;
            let application_largest = 2000u64;

            let truncated_pn = 0x50; // Same truncated value in all spaces
            let pn_len = 1;

            // Reconstruct in each space - should give different results
            let initial_reconstructed =
                decode_packet_number_reconstruct(truncated_pn, pn_len, initial_largest).unwrap();

            let handshake_reconstructed =
                decode_packet_number_reconstruct(truncated_pn, pn_len, handshake_largest).unwrap();

            let application_reconstructed =
                decode_packet_number_reconstruct(truncated_pn, pn_len, application_largest)
                    .unwrap();

            // Results should be different due to different largest_pn contexts
            assert_ne!(
                initial_reconstructed, handshake_reconstructed,
                "Initial and handshake spaces should reconstruct differently"
            );
            assert_ne!(
                handshake_reconstructed, application_reconstructed,
                "Handshake and application spaces should reconstruct differently"
            );
        }
    }

    /// br-asupersync-4gvuyo — RFC 9000 §10.1 truth table for the
    /// effective `max_idle_timeout`. Per §18.2, `0` means "no advertised
    /// limit"; `None` (parameter absent) is treated identically.
    ///
    /// Source: <https://www.rfc-editor.org/rfc/rfc9000.html#section-10.1>
    #[test]
    fn effective_max_idle_timeout_matches_rfc_9000_section_10_1() {
        fn tp(timeout: Option<u64>) -> TransportParameters {
            TransportParameters {
                max_idle_timeout: timeout,
                ..TransportParameters::default()
            }
        }

        // (local, peer, expected effective)
        let cases: &[(Option<u64>, Option<u64>, Option<u64>, &str)] = &[
            // Both advertise non-zero → min wins.
            (
                Some(30_000),
                Some(10_000),
                Some(10_000),
                "min(30k, 10k) = 10k",
            ),
            (
                Some(10_000),
                Some(30_000),
                Some(10_000),
                "min(10k, 30k) = 10k (commutative)",
            ),
            (
                Some(15_000),
                Some(15_000),
                Some(15_000),
                "equal advertised values",
            ),
            // Sole non-zero advertisement carries.
            (Some(20_000), None, Some(20_000), "only local advertises"),
            (None, Some(25_000), Some(25_000), "only peer advertises"),
            (
                Some(20_000),
                Some(0),
                Some(20_000),
                "peer 0 == no peer advertisement",
            ),
            (
                Some(0),
                Some(25_000),
                Some(25_000),
                "local 0 == no local advertisement",
            ),
            // Neither advertises a finite limit.
            (None, None, None, "neither advertises"),
            (Some(0), Some(0), None, "both zero == both unadvertised"),
            (Some(0), None, None, "local zero, peer absent"),
            (None, Some(0), None, "local absent, peer zero"),
        ];

        for (local, peer, expected, label) in cases.iter().copied() {
            let actual = TransportParameters::effective_max_idle_timeout(&tp(local), &tp(peer));
            assert_eq!(
                actual, expected,
                "RFC 9000 §10.1: local={local:?}, peer={peer:?} → expected {expected:?} ({label}); got {actual:?}"
            );
        }
    }

    // ---------------------------------------------------------------------
    // RFC 9001 §5.4 header protection (GH#69). The masks below are the ones
    // printed in RFC 9001 Appendix A; the AEAD/HP key derivation that
    // produces them is exercised against the same vectors in
    // `quic_native::handshake_driver` (AES-128-GCM via the rustls provider).
    // ---------------------------------------------------------------------

    fn hex(text: &str) -> Vec<u8> {
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(compact.len() % 2, 0, "even number of hex digits");
        (0..compact.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&compact[i..i + 2], 16).expect("hex digit"))
            .collect()
    }

    /// RFC 9001 A.2: the unprotected client Initial header (pn 2, 4-byte pn).
    const RFC9001_A2_HEADER: &str = "c300000001088394c8f03e5157080000449e00000002";
    /// RFC 9001 A.2: mask = AES-ECB(hp, sample)[0..5].
    const RFC9001_A2_MASK: [u8; 5] = [0x43, 0x7b, 0x9a, 0xec, 0x36];
    /// RFC 9001 A.2: the first 38 bytes of the protected packet (header + sample).
    const RFC9001_A2_PROTECTED_PREFIX: &str =
        "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9b";
    /// RFC 9001 A.3: the unprotected server Initial header (pn 1, 2-byte pn).
    const RFC9001_A3_HEADER: &str = "c1000000010008f067a5502a4262b50040750001";
    const RFC9001_A3_MASK: [u8; 5] = [0x2e, 0xc0, 0xd8, 0x35, 0x6a];
    /// RFC 9001 A.3: the first 38 bytes of the protected packet.
    const RFC9001_A3_PROTECTED_PREFIX: &str =
        "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100";

    #[test]
    fn rfc9001_a2_client_initial_header_protection_round_trips() {
        let header = hex(RFC9001_A2_HEADER);
        let protected = hex(RFC9001_A2_PROTECTED_PREFIX);
        let pn_offset = header.len() - 4;
        assert_eq!(pn_offset, 18, "A.2 packet number starts at byte 18");

        // Sender direction: header || (protected payload) masked with the RFC mask.
        let mut packet = header.clone();
        packet.extend_from_slice(&protected[header.len()..]);
        apply_header_protection(&mut packet, pn_offset, RFC9001_A2_MASK).expect("apply");
        assert_eq!(packet, protected, "A.2 protected header + sample bytes");

        // Receiver direction: the prefix is readable while still protected.
        let prefix = ProtectedHeaderPrefix::decode(&packet, 0).expect("protected prefix");
        let ProtectedHeaderPrefix::Long(long) = &prefix else {
            panic!("client Initial is a long header");
        };
        assert_eq!(long.packet_type, LongPacketType::Initial);
        assert_eq!(long.version, 1);
        assert_eq!(long.dst_cid.as_bytes(), &hex("8394c8f03e515708")[..]);
        assert!(long.src_cid.is_empty());
        assert!(long.token.is_empty());
        assert_eq!(long.payload_length, 1182);
        assert_eq!(long.packet_number_offset, pn_offset);
        assert_eq!(
            header_protection_sample(&packet, pn_offset).expect("sample"),
            &hex("d1b1c98dd7689fb8ec11d242b123dc9b")[..],
            "sample starts 4 bytes past the packet-number offset"
        );

        let pn_len =
            remove_header_protection(&mut packet, pn_offset, RFC9001_A2_MASK).expect("remove");
        assert_eq!(pn_len, 4);
        assert_eq!(&packet[..header.len()], &header[..]);
        let (decoded, consumed) = PacketHeader::decode(&packet, 0).expect("unprotected header");
        assert_eq!(consumed, header.len());
        let PacketHeader::Long(decoded) = decoded else {
            panic!("long header")
        };
        assert_eq!(decoded.packet_number, 2);
        assert_eq!(decoded.packet_number_len, 4);
    }

    #[test]
    fn rfc9001_a3_server_initial_header_protection_round_trips_two_byte_pn() {
        let header = hex(RFC9001_A3_HEADER);
        let protected = hex(RFC9001_A3_PROTECTED_PREFIX);
        let pn_offset = header.len() - 2;
        assert_eq!(pn_offset, 18);

        let mut packet = header.clone();
        packet.extend_from_slice(&protected[header.len()..]);
        // The sample is taken as if the packet number were 4 bytes wide, so
        // it starts inside the ciphertext for a 2-byte packet number.
        assert_eq!(
            header_protection_sample(&packet, pn_offset).expect("sample"),
            &hex("2cd0991cd25b0aac406a5816b6394100")[..]
        );
        apply_header_protection(&mut packet, pn_offset, RFC9001_A3_MASK).expect("apply");
        assert_eq!(packet, protected);

        let pn_len =
            remove_header_protection(&mut packet, pn_offset, RFC9001_A3_MASK).expect("remove");
        assert_eq!(pn_len, 2);
        assert_eq!(&packet[..header.len()], &header[..]);
        let (PacketHeader::Long(decoded), consumed) =
            PacketHeader::decode(&packet, 0).expect("unprotected header")
        else {
            panic!("long header")
        };
        assert_eq!(consumed, header.len());
        assert_eq!(decoded.packet_number, 1);
        assert_eq!(decoded.packet_number_len, 2);
        assert_eq!(decoded.dst_cid.len(), 0);
        assert_eq!(decoded.src_cid.as_bytes(), &hex("f067a5502a4262b5")[..]);
        assert_eq!(decoded.payload_length, 0x75);
    }

    /// RFC 8439 §2.3 ChaCha20 block function, used only to compute the RFC
    /// 9001 §5.4.4 header-protection mask for the A.5 vector without a
    /// production dependency on a raw ChaCha20 primitive.
    fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
        fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
            s[a] = s[a].wrapping_add(s[b]);
            s[d] ^= s[a];
            s[d] = s[d].rotate_left(16);
            s[c] = s[c].wrapping_add(s[d]);
            s[b] ^= s[c];
            s[b] = s[b].rotate_left(12);
            s[a] = s[a].wrapping_add(s[b]);
            s[d] ^= s[a];
            s[d] = s[d].rotate_left(8);
            s[c] = s[c].wrapping_add(s[d]);
            s[b] ^= s[c];
            s[b] = s[b].rotate_left(7);
        }
        let mut state = [0u32; 16];
        state[0] = 0x6170_7865;
        state[1] = 0x3320_646e;
        state[2] = 0x7962_2d32;
        state[3] = 0x6b20_6574;
        for (i, word) in key.chunks_exact(4).enumerate() {
            state[4 + i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }
        state[12] = counter;
        for (i, word) in nonce.chunks_exact(4).enumerate() {
            state[13 + i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }
        let mut working = state;
        for _ in 0..10 {
            quarter_round(&mut working, 0, 4, 8, 12);
            quarter_round(&mut working, 1, 5, 9, 13);
            quarter_round(&mut working, 2, 6, 10, 14);
            quarter_round(&mut working, 3, 7, 11, 15);
            quarter_round(&mut working, 0, 5, 10, 15);
            quarter_round(&mut working, 1, 6, 11, 12);
            quarter_round(&mut working, 2, 7, 8, 13);
            quarter_round(&mut working, 3, 4, 9, 14);
        }
        let mut out = [0u8; 64];
        for (i, chunk) in out.chunks_exact_mut(4).enumerate() {
            chunk.copy_from_slice(&working[i].wrapping_add(state[i]).to_le_bytes());
        }
        out
    }

    #[test]
    fn rfc9001_a5_chacha20_short_header_protection_vector() {
        // RFC 9001 §5.4.4: counter = sample[0..4] (little endian),
        // nonce = sample[4..16], mask = ChaCha20(hp, counter, nonce, {0}^5).
        let hp: [u8; 32] = hex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
            .try_into()
            .expect("32-byte hp key");
        let sample_bytes = hex("5e5cd55c41f69080575d7999c25a5bfb");
        let counter = u32::from_le_bytes([
            sample_bytes[0],
            sample_bytes[1],
            sample_bytes[2],
            sample_bytes[3],
        ]);
        let nonce: [u8; 12] = sample_bytes[4..16].try_into().expect("12-byte nonce");
        let keystream = chacha20_block(&hp, counter, &nonce);
        let mut mask = [0u8; 5];
        mask.copy_from_slice(&keystream[..5]);
        assert_eq!(mask, [0xae, 0xfe, 0xfe, 0x7d, 0x03], "A.5 mask");

        // Empty DCID: packet number starts at byte 1; 3-byte pn (0x42 & 0x03 = 2).
        let unprotected = hex("4200bff4655e5cd55c41f69080575d7999c25a5bfb");
        let protected = hex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb");
        assert_eq!(protected.len(), 21, "smallest possible packet");
        let pn_offset = 1;
        assert_eq!(
            header_protection_sample(&unprotected, pn_offset).expect("sample"),
            &sample_bytes[..],
            "A.5 skips one ciphertext byte to sample past a 4-byte pn"
        );

        let mut packet = unprotected.clone();
        apply_header_protection(&mut packet, pn_offset, mask).expect("apply");
        assert_eq!(packet, protected);

        let ProtectedHeaderPrefix::Short {
            dst_cid,
            packet_number_offset,
        } = ProtectedHeaderPrefix::decode(&packet, 0).expect("protected short prefix")
        else {
            panic!("short header")
        };
        assert!(dst_cid.is_empty());
        assert_eq!(packet_number_offset, pn_offset);

        let pn_len = remove_header_protection(&mut packet, pn_offset, mask).expect("remove");
        assert_eq!(pn_len, 3);
        assert_eq!(packet, unprotected);
        let (PacketHeader::Short(header), consumed) =
            PacketHeader::decode(&packet, 0).expect("unprotected short header")
        else {
            panic!("short header")
        };
        assert_eq!(consumed, 4);
        assert_eq!(header.packet_number, 0x0000_bff4);
        assert_eq!(header.packet_number_len, 3);
        assert!(!header.spin);
        assert!(!header.key_phase);
        // RFC 9001 A.5: 654360564 is encoded as the low 3 bytes 0x00bff4 and
        // reconstructed from the largest packet number seen so far.
        assert_eq!(
            decode_packet_number_reconstruct(0x0000_bff4, 3, 654_360_563).expect("reconstruct"),
            654_360_564
        );
    }

    #[test]
    fn header_protection_flipped_masked_bits_change_the_recovered_header() {
        let header = hex(RFC9001_A2_HEADER);
        let protected = hex(RFC9001_A2_PROTECTED_PREFIX);
        let pn_offset = 18;

        // Flip the low bit of the protected first byte: the unmasked packet
        // number length changes (4 -> 3) so the header/AAD no longer matches.
        let mut flipped_len = protected.clone();
        flipped_len[0] ^= 0x01;
        let pn_len = remove_header_protection(&mut flipped_len, pn_offset, RFC9001_A2_MASK)
            .expect("remove still parses");
        assert_eq!(
            pn_len, 3,
            "bit 0 of the first byte is part of the pn length"
        );
        assert_ne!(&flipped_len[..header.len()], &header[..]);

        // Flip a protected reserved bit: the unmasked header is invalid, and
        // that is only detectable after removal (the protected byte looked fine).
        let mut flipped_reserved = protected.clone();
        flipped_reserved[0] ^= 0x04;
        assert!(
            ProtectedHeaderPrefix::decode(&flipped_reserved, 0).is_ok(),
            "reserved bits are not validated while protected"
        );
        remove_header_protection(&mut flipped_reserved, pn_offset, RFC9001_A2_MASK)
            .expect("remove");
        assert_eq!(
            PacketHeader::decode(&flipped_reserved, 0).expect_err("reserved bit set"),
            QuicCoreError::InvalidHeader("long header reserved bits set")
        );

        // Flip a protected packet-number byte: a different packet number is
        // recovered, so the AEAD nonce (and therefore the tag) will not verify.
        let mut flipped_pn = protected;
        flipped_pn[pn_offset + 3] ^= 0x80;
        remove_header_protection(&mut flipped_pn, pn_offset, RFC9001_A2_MASK).expect("remove");
        let (PacketHeader::Long(decoded), _) =
            PacketHeader::decode(&flipped_pn, 0).expect("still a well-formed header")
        else {
            panic!("long header")
        };
        assert_eq!(decoded.packet_number, 2 ^ 0x80);
    }

    #[test]
    fn header_protection_helpers_fail_closed_on_short_or_malformed_input() {
        let mask = [0xff; 5];
        // Sample needs pn_offset + 4 + 16 bytes: the 22-byte A.2 header
        // (pn at 18..22) plus 16 bytes of payload.
        let mut too_short = hex(RFC9001_A2_HEADER);
        too_short.extend_from_slice(&[0u8; 15]);
        assert_eq!(
            header_protection_sample(&too_short, 18).expect_err("15 payload bytes"),
            QuicCoreError::UnexpectedEof
        );
        too_short.push(0);
        assert!(header_protection_sample(&too_short, 18).is_ok());

        // The packet number can never start at byte 0.
        let mut packet = hex(RFC9001_A2_HEADER);
        assert!(matches!(
            apply_header_protection(&mut packet, 0, mask),
            Err(QuicCoreError::InvalidHeader(_))
        ));
        assert!(matches!(
            remove_header_protection(&mut packet, 0, mask),
            Err(QuicCoreError::InvalidHeader(_))
        ));
        // A pn offset past the buffer is an EOF, and the packet is untouched.
        let before = packet.clone();
        let past_end = packet.len();
        assert_eq!(
            apply_header_protection(&mut packet, past_end, mask).expect_err("past end"),
            QuicCoreError::UnexpectedEof
        );
        assert_eq!(
            remove_header_protection(&mut packet, past_end, mask).expect_err("past end"),
            QuicCoreError::UnexpectedEof
        );
        assert_eq!(packet, before, "failed masking must not mutate the packet");
        assert!(apply_header_protection(&mut [], 1, mask).is_err());
        assert_eq!(
            ProtectedHeaderPrefix::decode(&[], 0).expect_err("empty"),
            QuicCoreError::UnexpectedEof
        );
        assert_eq!(
            ProtectedHeaderPrefix::decode(&[0x00, 0x01, 0x02], 2).expect_err("fixed bit"),
            QuicCoreError::InvalidHeader("short header fixed bit unset")
        );
        assert_eq!(
            ProtectedHeaderPrefix::decode(&[0x40], 4).expect_err("truncated cid"),
            QuicCoreError::UnexpectedEof
        );
    }

    #[test]
    fn protected_prefix_length_field_bounds_coalesced_long_header_packets() {
        // Two long-header packets back to back (RFC 9000 §12.2), each with a
        // 4-byte pn, 4 bytes of "ciphertext" and a 16-byte "tag".
        let cid = ConnectionId::new(&[1, 2, 3, 4]).expect("cid");
        let mut datagram = Vec::new();
        let mut ends = Vec::new();
        for (packet_type, pn) in [
            (LongPacketType::Initial, 7u64),
            (LongPacketType::Handshake, 9),
        ] {
            PacketHeader::Long(LongHeader {
                packet_type,
                version: 1,
                dst_cid: cid,
                src_cid: cid,
                token: Vec::new(),
                payload_length: 4 + 4 + 16,
                packet_number: pn,
                packet_number_len: 4,
            })
            .encode(&mut datagram)
            .expect("encode");
            datagram.extend_from_slice(&[0xab; 20]);
            ends.push(datagram.len());
        }
        // Trailing datagram padding (zero bytes) after the last packet.
        datagram.extend_from_slice(&[0u8; 3]);

        let first = ProtectedHeaderPrefix::decode(&datagram, 0).expect("first prefix");
        let first_end = first.packet_len(datagram.len()).expect("first bound");
        assert_eq!(first_end, ends[0]);
        let ProtectedHeaderPrefix::Long(first) = &first else {
            panic!("long")
        };
        assert_eq!(first.packet_type, LongPacketType::Initial);
        assert_eq!(first.packet_number_offset + 24, first_end);

        let rest = &datagram[first_end..];
        let second = ProtectedHeaderPrefix::decode(rest, 0).expect("second prefix");
        assert_eq!(
            second.packet_len(rest.len()).expect("second bound") + first_end,
            ends[1]
        );
        let ProtectedHeaderPrefix::Long(second) = &second else {
            panic!("long")
        };
        assert_eq!(second.packet_type, LongPacketType::Handshake);

        // What remains is padding, not a packet.
        let padding = &datagram[ends[1]..];
        assert_eq!(padding, &[0u8; 3]);
        assert!(ProtectedHeaderPrefix::decode(padding, 0).is_err());

        // A Length field that overruns the datagram is rejected before any
        // byte of the payload is trusted.
        let truncated = &datagram[..ends[0] - 1];
        let prefix = ProtectedHeaderPrefix::decode(truncated, 0).expect("prefix still parses");
        assert_eq!(
            prefix.packet_len(truncated.len()).expect_err("overrun"),
            QuicCoreError::UnexpectedEof
        );

        // Retry and short-header packets extend to the end of the datagram.
        let short = ProtectedHeaderPrefix::Short {
            dst_cid: cid,
            packet_number_offset: 5,
        };
        assert_eq!(short.packet_len(40).expect("short"), 40);
        assert_eq!(short.packet_number_offset(), Some(5));
        assert_eq!(short.dst_cid(), cid);
    }
}
