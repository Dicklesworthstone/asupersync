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
    ///
    /// Values that RFC 9000 §18.2 makes invalid (and that [`Self::decode`]
    /// therefore rejects from a peer) fail with
    /// [`QuicCoreError::InvalidTransportParameter`] before anything is
    /// written to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), QuicCoreError> {
        for (id, value) in [
            (TP_MAX_UDP_PAYLOAD_SIZE, self.max_udp_payload_size),
            (TP_INITIAL_MAX_STREAMS_BIDI, self.initial_max_streams_bidi),
            (TP_INITIAL_MAX_STREAMS_UNI, self.initial_max_streams_uni),
            (TP_ACK_DELAY_EXPONENT, self.ack_delay_exponent),
            (TP_MAX_ACK_DELAY, self.max_ack_delay),
        ] {
            if let Some(value) = value {
                check_known_u64(id, value)?;
            }
        }
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
            let len = usize::try_from(len).map_err(|_| QuicCoreError::UnexpectedEof)?;
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
                    set_checked_u64(&mut tp.max_udp_payload_size, id, value)?;
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
                    set_checked_u64(&mut tp.initial_max_streams_bidi, id, value)?;
                }
                TP_INITIAL_MAX_STREAMS_UNI => {
                    set_checked_u64(&mut tp.initial_max_streams_uni, id, value)?;
                }
                TP_ACK_DELAY_EXPONENT => {
                    set_checked_u64(&mut tp.ack_delay_exponent, id, value)?;
                }
                TP_MAX_ACK_DELAY => {
                    set_checked_u64(&mut tp.max_ack_delay, id, value)?;
                }
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
        let token_len = usize::try_from(token_len).map_err(|_| QuicCoreError::UnexpectedEof)?;
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

/// RFC 9000 §18.2 value constraints on the integer transport parameters.
/// Encode and decode share this predicate, so an endpoint never sends a
/// value it would reject from its peer.
fn check_known_u64(id: u64, value: u64) -> Result<(), QuicCoreError> {
    let valid = match id {
        TP_MAX_UDP_PAYLOAD_SIZE => value >= 1200,
        // §4.6: a limit above 2^60 allows stream IDs that no varint can encode.
        TP_INITIAL_MAX_STREAMS_BIDI | TP_INITIAL_MAX_STREAMS_UNI => value <= 1 << 60,
        TP_ACK_DELAY_EXPONENT => value <= 20,
        // Delays of 2^14 ms or greater are invalid.
        TP_MAX_ACK_DELAY => value < 1 << 14,
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(QuicCoreError::InvalidTransportParameter(id))
    }
}

fn set_checked_u64(slot: &mut Option<u64>, id: u64, value: &[u8]) -> Result<(), QuicCoreError> {
    set_unique_u64(slot, id, value)?;
    slot.map_or(Ok(()), |decoded| check_known_u64(id, decoded))
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
#[path = "mod_inline_tests.rs"]
mod tests;
