//! Tokio-free QUIC transport core primitives.
//!
//! Phase 1 scope:
//! - QUIC varint codec
//! - Connection ID representation
//! - Initial/short packet header codecs
//! - Transport parameter TLV codec
//!
//! This module is intentionally runtime-agnostic and memory-safe.

use std::fmt;

/// Maximum value representable by QUIC varint (2^62 - 1).
pub const QUIC_VARINT_MAX: u64 = (1u64 << 62) - 1;

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
    /// Retry long-header packets are not yet supported in this phase.
    UnsupportedRetryPacket,
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
            Self::UnsupportedRetryPacket => write!(f, "retry packet not supported in phase 1"),
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
    /// Truncated packet number value.
    pub packet_number: u32,
    /// Encoded packet-number width in bytes (`1..=4`).
    pub packet_number_len: u8,
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
    /// Truncated packet number value.
    pub packet_number: u32,
    /// Encoded packet-number width in bytes (`1..=4`).
    pub packet_number_len: u8,
}

/// QUIC packet header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketHeader {
    /// Long-header packet.
    Long(LongHeader),
    /// Short-header packet.
    Short(ShortHeader),
}

impl PacketHeader {
    /// Encode packet header into `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), QuicCoreError> {
        match self {
            Self::Long(h) => encode_long_header(h, out),
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
            decode_long_header(input).map(|(h, n)| (Self::Long(h), n))
        } else {
            decode_short_header(input, short_dcid_len).map(|(h, n)| (Self::Short(h), n))
        }
    }
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
                _ => tp.unknown.push(UnknownTransportParameter {
                    id,
                    value: value.to_vec(),
                }),
            }
        }
        Ok(tp)
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

fn decode_long_header(input: &[u8]) -> Result<(LongHeader, usize), QuicCoreError> {
    if input.len() < 6 {
        return Err(QuicCoreError::UnexpectedEof);
    }
    let first = input[0];
    if first & 0x40 == 0 {
        return Err(QuicCoreError::InvalidHeader("long header fixed bit unset"));
    }
    if first & 0x0c != 0 {
        return Err(QuicCoreError::InvalidHeader(
            "long header reserved bits set",
        ));
    }
    let pn_len = (first & 0x03) + 1;
    let packet_type = match (first >> 4) & 0x03 {
        0 => LongPacketType::Initial,
        1 => LongPacketType::ZeroRtt,
        2 => LongPacketType::Handshake,
        3 => return Err(QuicCoreError::UnsupportedRetryPacket),
        _ => unreachable!("2-bit pattern"),
    };

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

    let token = if matches!(packet_type, LongPacketType::Initial) {
        let (token_len, consumed) = decode_varint(&input[pos..])?;
        pos += consumed;
        let token_len = token_len as usize;
        if input.len().saturating_sub(pos) < token_len {
            return Err(QuicCoreError::UnexpectedEof);
        }
        let token = input[pos..pos + token_len].to_vec();
        pos += token_len;
        token
    } else {
        Vec::new()
    };

    let (payload_length, consumed) = decode_varint(&input[pos..])?;
    pos += consumed;
    if payload_length < u64::from(pn_len) {
        return Err(QuicCoreError::InvalidHeader(
            "payload length smaller than packet number length",
        ));
    }

    let packet_number = read_packet_number(input, &mut pos, pn_len)?;
    Ok((
        LongHeader {
            packet_type,
            version,
            dst_cid,
            src_cid,
            token,
            payload_length,
            packet_number,
            packet_number_len: pn_len,
        },
        pos,
    ))
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

    let mut pos = 1usize;
    let dst_cid = read_cid(input, &mut pos, short_dcid_len)?;
    let packet_number = read_packet_number(input, &mut pos, pn_len)?;
    Ok((
        ShortHeader {
            spin,
            key_phase,
            dst_cid,
            packet_number,
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

fn write_packet_number(packet_number: u32, width: u8, out: &mut Vec<u8>) {
    let bytes = packet_number.to_be_bytes();
    let take = width as usize;
    out.extend_from_slice(&bytes[4 - take..]);
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

fn ensure_pn_fits(packet_number: u32, packet_number_len: u8) -> Result<(), QuicCoreError> {
    let max = match packet_number_len {
        1 => 0xff,
        2 => 0xffff,
        3 => 0x00ff_ffff,
        4 => u32::MAX,
        _ => return Err(QuicCoreError::InvalidHeader("invalid packet number length")),
    };
    if packet_number <= max {
        Ok(())
    } else {
        Err(QuicCoreError::PacketNumberTooLarge {
            packet_number,
            width: packet_number_len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn retry_long_packet_rejected() {
        // Long header with retry type bits (11).
        let raw = [0b1111_0000, 0, 0, 0, 1, 0, 0];
        let err = PacketHeader::decode(&raw, 0).expect_err("should fail");
        assert_eq!(err, QuicCoreError::UnsupportedRetryPacket);
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
            (QuicCoreError::VarIntOutOfRange(99), "varint out of range: 99"),
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
            (
                QuicCoreError::UnsupportedRetryPacket,
                "retry packet not supported in phase 1",
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
            version: 0x00000001,
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
            version: 0xff00001d,
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
}
