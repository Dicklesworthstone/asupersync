//! QUIC Frame Codecs for ATP Transport
//!
//! Implements standard QUIC frame encoding/decoding that ATP can use as an
//! underlying transport. This provides the frame layer needed for QUIC packet
//! assembly and parsing.
//!
//! Frame types implemented:
//! - ACK: Acknowledge received packets
//! - PING: Keep-alive and path validation
//! - CONNECTION_CLOSE: Terminate connection
//! - CRYPTO: TLS handshake data
//! - STREAM: Application data streams
//! - RESET_STREAM: Abort stream transmission
//! - STOP_SENDING: Request stream termination
//! - MAX_DATA: Connection-level flow control
//! - MAX_STREAM_DATA: Stream-level flow control
//! - MAX_STREAMS: Stream count limits
//! - DATA_BLOCKED: Connection flow control blocked
//! - STREAM_DATA_BLOCKED: Stream flow control blocked
//! - PATH_CHALLENGE: Path validation request
//! - PATH_RESPONSE: Path validation response
//! - HANDSHAKE_DONE: TLS handshake completion

use crate::bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::net::atp::protocol::varint::{VarInt, VarIntError};
use crate::types::outcome::Outcome;

/// QUIC frame type constants as defined in RFC 9000
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u64)]
pub enum QuicFrameType {
    /// PADDING frame
    Padding = 0x00,
    /// PING frame
    Ping = 0x01,
    /// ACK frame (without ECN)
    Ack = 0x02,
    /// ACK frame (with ECN)
    AckEcn = 0x03,
    /// RESET_STREAM frame
    ResetStream = 0x04,
    /// STOP_SENDING frame
    StopSending = 0x05,
    /// CRYPTO frame
    Crypto = 0x06,
    /// NEW_TOKEN frame
    NewToken = 0x07,
    /// STREAM frames (0x08-0x0f, with bits for OFF/LEN/FIN)
    StreamBase = 0x08,
    /// MAX_DATA frame
    MaxData = 0x10,
    /// MAX_STREAM_DATA frame
    MaxStreamData = 0x11,
    /// MAX_STREAMS frame (bidirectional)
    MaxStreamsBidi = 0x12,
    /// MAX_STREAMS frame (unidirectional)
    MaxStreamsUni = 0x13,
    /// DATA_BLOCKED frame
    DataBlocked = 0x14,
    /// STREAM_DATA_BLOCKED frame
    StreamDataBlocked = 0x15,
    /// STREAMS_BLOCKED frame (bidirectional)
    StreamsBlockedBidi = 0x16,
    /// STREAMS_BLOCKED frame (unidirectional)
    StreamsBlockedUni = 0x17,
    /// NEW_CONNECTION_ID frame
    NewConnectionId = 0x18,
    /// RETIRE_CONNECTION_ID frame
    RetireConnectionId = 0x19,
    /// PATH_CHALLENGE frame
    PathChallenge = 0x1a,
    /// PATH_RESPONSE frame
    PathResponse = 0x1b,
    /// CONNECTION_CLOSE frame (QUIC)
    ConnectionCloseQuic = 0x1c,
    /// CONNECTION_CLOSE frame (Application)
    ConnectionCloseApp = 0x1d,
    /// HANDSHAKE_DONE frame
    HandshakeDone = 0x1e,
}

impl QuicFrameType {
    /// Convert to wire format varint
    pub fn to_varint(self) -> VarInt {
        match VarInt::new(self as u64) {
            Outcome::Ok(varint) => varint,
            _ => panic!("frame type fits in varint"),
        }
    }

    /// Parse from wire format varint
    pub fn from_varint(varint: VarInt) -> Result<Self, QuicFrameError> {
        let value = varint.value();
        match value {
            0x00 => Ok(QuicFrameType::Padding),
            0x01 => Ok(QuicFrameType::Ping),
            0x02 => Ok(QuicFrameType::Ack),
            0x03 => Ok(QuicFrameType::AckEcn),
            0x04 => Ok(QuicFrameType::ResetStream),
            0x05 => Ok(QuicFrameType::StopSending),
            0x06 => Ok(QuicFrameType::Crypto),
            0x07 => Ok(QuicFrameType::NewToken),
            0x08..=0x0f => Ok(QuicFrameType::StreamBase), // STREAM frames with flags
            0x10 => Ok(QuicFrameType::MaxData),
            0x11 => Ok(QuicFrameType::MaxStreamData),
            0x12 => Ok(QuicFrameType::MaxStreamsBidi),
            0x13 => Ok(QuicFrameType::MaxStreamsUni),
            0x14 => Ok(QuicFrameType::DataBlocked),
            0x15 => Ok(QuicFrameType::StreamDataBlocked),
            0x16 => Ok(QuicFrameType::StreamsBlockedBidi),
            0x17 => Ok(QuicFrameType::StreamsBlockedUni),
            0x18 => Ok(QuicFrameType::NewConnectionId),
            0x19 => Ok(QuicFrameType::RetireConnectionId),
            0x1a => Ok(QuicFrameType::PathChallenge),
            0x1b => Ok(QuicFrameType::PathResponse),
            0x1c => Ok(QuicFrameType::ConnectionCloseQuic),
            0x1d => Ok(QuicFrameType::ConnectionCloseApp),
            0x1e => Ok(QuicFrameType::HandshakeDone),
            other => Err(QuicFrameError::UnknownFrameType(other)),
        }
    }

    /// Check if this is a STREAM frame type
    pub fn is_stream_frame(value: u64) -> bool {
        (value & 0xf8) == 0x08
    }
}

/// QUIC Frame definitions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicFrame {
    /// PADDING frame
    Padding {
        /// Number of padding bytes
        length: usize,
    },

    /// PING frame (no payload)
    Ping,

    /// ACK frame
    Ack {
        /// Largest acknowledged packet number
        largest_acknowledged: VarInt,
        /// ACK delay in microseconds
        ack_delay: VarInt,
        /// Number of ACK range count
        ack_range_count: VarInt,
        /// First ACK range length
        first_ack_range: VarInt,
        /// Additional ACK ranges
        ack_ranges: Vec<AckRange>,
        /// ECN counts (if present)
        ecn_counts: Option<EcnCounts>,
    },

    /// RESET_STREAM frame
    ResetStream {
        /// Stream ID
        stream_id: VarInt,
        /// Application error code
        error_code: VarInt,
        /// Final size
        final_size: VarInt,
    },

    /// STOP_SENDING frame
    StopSending {
        /// Stream ID
        stream_id: VarInt,
        /// Application error code
        error_code: VarInt,
    },

    /// CRYPTO frame
    Crypto {
        /// Offset in the crypto stream
        offset: VarInt,
        /// Crypto data
        data: Bytes,
    },

    /// STREAM frame
    Stream {
        /// Stream ID
        stream_id: VarInt,
        /// Offset in the stream (if present)
        offset: Option<VarInt>,
        /// Stream data
        data: Bytes,
        /// FIN flag
        fin: bool,
    },

    /// MAX_DATA frame
    MaxData {
        /// Maximum data
        maximum_data: VarInt,
    },

    /// MAX_STREAM_DATA frame
    MaxStreamData {
        /// Stream ID
        stream_id: VarInt,
        /// Maximum stream data
        maximum_stream_data: VarInt,
    },

    /// MAX_STREAMS frame
    MaxStreams {
        /// Maximum streams
        maximum_streams: VarInt,
        /// Bidirectional streams
        bidirectional: bool,
    },

    /// DATA_BLOCKED frame
    DataBlocked {
        /// Maximum data
        maximum_data: VarInt,
    },

    /// STREAM_DATA_BLOCKED frame
    StreamDataBlocked {
        /// Stream ID
        stream_id: VarInt,
        /// Maximum stream data
        maximum_stream_data: VarInt,
    },

    /// STREAMS_BLOCKED frame
    StreamsBlocked {
        /// Maximum streams
        maximum_streams: VarInt,
        /// Bidirectional streams
        bidirectional: bool,
    },

    /// PATH_CHALLENGE frame
    PathChallenge {
        /// 8-byte challenge data
        data: [u8; 8],
    },

    /// PATH_RESPONSE frame
    PathResponse {
        /// 8-byte response data
        data: [u8; 8],
    },

    /// CONNECTION_CLOSE frame
    ConnectionClose {
        /// Error code
        error_code: VarInt,
        /// Frame type that caused the error (for QUIC close)
        frame_type: Option<VarInt>,
        /// Human-readable reason phrase
        reason_phrase: Bytes,
    },

    /// HANDSHAKE_DONE frame (no payload)
    HandshakeDone,
}

/// ACK range in an ACK frame
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckRange {
    /// Gap to next range
    pub gap: VarInt,
    /// ACK range length
    pub ack_range_length: VarInt,
}

/// ECN counts in an ACK frame
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcnCounts {
    /// ECT(0) count
    pub ect0_count: VarInt,
    /// ECT(1) count
    pub ect1_count: VarInt,
    /// ECN-CE count
    pub ecn_ce_count: VarInt,
}

/// QUIC frame encoding/decoding errors
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QuicFrameError {
    /// Varint encoding/decoding error
    #[error("varint error: {0}")]
    VarInt(#[from] VarIntError),

    /// Unknown frame type
    #[error("unknown frame type: {0}")]
    UnknownFrameType(u64),

    /// Invalid frame format
    #[error("invalid frame format: {0}")]
    InvalidFormat(String),

    /// Unexpected end of frame data
    #[error("unexpected end of frame data")]
    UnexpectedEof,

    /// Frame payload too large
    #[error("frame payload too large: {size} bytes")]
    PayloadTooLarge {
        /// Observed payload size.
        size: usize,
    },
}

impl QuicFrame {
    /// Encode frame to buffer
    pub fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), QuicFrameError> {
        match self {
            QuicFrame::Padding { length } => {
                // PADDING frames are just zeros
                for _ in 0..*length {
                    buf.put_u8(0x00);
                }
            }

            QuicFrame::Ping => {
                QuicFrameType::Ping.to_varint().encode_to_buf(buf)?;
            }

            QuicFrame::Ack {
                largest_acknowledged,
                ack_delay,
                ack_range_count,
                first_ack_range,
                ack_ranges,
                ecn_counts,
            } => {
                // Frame type
                if ecn_counts.is_some() {
                    QuicFrameType::AckEcn.to_varint().encode_to_buf(buf)?;
                } else {
                    QuicFrameType::Ack.to_varint().encode_to_buf(buf)?;
                }

                // ACK fields
                largest_acknowledged.encode_to_buf(buf)?;
                ack_delay.encode_to_buf(buf)?;
                ack_range_count.encode_to_buf(buf)?;
                first_ack_range.encode_to_buf(buf)?;

                // ACK ranges
                for range in ack_ranges {
                    range.gap.encode_to_buf(buf)?;
                    range.ack_range_length.encode_to_buf(buf)?;
                }

                // ECN counts (if present)
                if let Some(ecn) = ecn_counts {
                    ecn.ect0_count.encode_to_buf(buf)?;
                    ecn.ect1_count.encode_to_buf(buf)?;
                    ecn.ecn_ce_count.encode_to_buf(buf)?;
                }
            }

            QuicFrame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                QuicFrameType::ResetStream.to_varint().encode_to_buf(buf)?;
                stream_id.encode_to_buf(buf)?;
                error_code.encode_to_buf(buf)?;
                final_size.encode_to_buf(buf)?;
            }

            QuicFrame::StopSending {
                stream_id,
                error_code,
            } => {
                QuicFrameType::StopSending.to_varint().encode_to_buf(buf)?;
                stream_id.encode_to_buf(buf)?;
                error_code.encode_to_buf(buf)?;
            }

            QuicFrame::Crypto { offset, data } => {
                QuicFrameType::Crypto.to_varint().encode_to_buf(buf)?;
                offset.encode_to_buf(buf)?;
                match VarInt::new(data.len() as u64) {
                    Outcome::Ok(varint) => varint.encode_to_buf(buf)?,
                    _ => {
                        return Err(QuicFrameError::InvalidFormat(
                            "Invalid crypto data length".to_string(),
                        ));
                    }
                }
                buf.put_slice(data);
            }

            QuicFrame::Stream {
                stream_id,
                offset,
                data,
                fin,
            } => {
                // Construct STREAM frame type with flags
                let mut frame_type = QuicFrameType::StreamBase as u64;
                if offset.is_some() {
                    frame_type |= 0x04; // OFF bit
                }
                if !data.is_empty() {
                    frame_type |= 0x02; // LEN bit
                }
                if *fin {
                    frame_type |= 0x01; // FIN bit
                }

                match VarInt::new(frame_type) {
                    Outcome::Ok(varint) => varint.encode_to_buf(buf)?,
                    _ => {
                        return Err(QuicFrameError::InvalidFormat(
                            "Invalid frame type".to_string(),
                        ));
                    }
                }
                stream_id.encode_to_buf(buf)?;

                if let Some(offset_val) = offset {
                    offset_val.encode_to_buf(buf)?;
                }

                if !data.is_empty() {
                    match VarInt::new(data.len() as u64) {
                        Outcome::Ok(varint) => varint.encode_to_buf(buf)?,
                        _ => {
                            return Err(QuicFrameError::InvalidFormat(
                                "Invalid data length".to_string(),
                            ));
                        }
                    }
                }

                buf.put_slice(data);
            }

            QuicFrame::MaxData { maximum_data } => {
                QuicFrameType::MaxData.to_varint().encode_to_buf(buf)?;
                maximum_data.encode_to_buf(buf)?;
            }

            QuicFrame::MaxStreamData {
                stream_id,
                maximum_stream_data,
            } => {
                QuicFrameType::MaxStreamData
                    .to_varint()
                    .encode_to_buf(buf)?;
                stream_id.encode_to_buf(buf)?;
                maximum_stream_data.encode_to_buf(buf)?;
            }

            QuicFrame::MaxStreams {
                maximum_streams,
                bidirectional,
            } => {
                if *bidirectional {
                    QuicFrameType::MaxStreamsBidi
                        .to_varint()
                        .encode_to_buf(buf)?;
                } else {
                    QuicFrameType::MaxStreamsUni
                        .to_varint()
                        .encode_to_buf(buf)?;
                }
                maximum_streams.encode_to_buf(buf)?;
            }

            QuicFrame::DataBlocked { maximum_data } => {
                QuicFrameType::DataBlocked.to_varint().encode_to_buf(buf)?;
                maximum_data.encode_to_buf(buf)?;
            }

            QuicFrame::StreamDataBlocked {
                stream_id,
                maximum_stream_data,
            } => {
                QuicFrameType::StreamDataBlocked
                    .to_varint()
                    .encode_to_buf(buf)?;
                stream_id.encode_to_buf(buf)?;
                maximum_stream_data.encode_to_buf(buf)?;
            }

            QuicFrame::StreamsBlocked {
                maximum_streams,
                bidirectional,
            } => {
                if *bidirectional {
                    QuicFrameType::StreamsBlockedBidi
                        .to_varint()
                        .encode_to_buf(buf)?;
                } else {
                    QuicFrameType::StreamsBlockedUni
                        .to_varint()
                        .encode_to_buf(buf)?;
                }
                maximum_streams.encode_to_buf(buf)?;
            }

            QuicFrame::PathChallenge { data } => {
                QuicFrameType::PathChallenge
                    .to_varint()
                    .encode_to_buf(buf)?;
                buf.put_slice(data);
            }

            QuicFrame::PathResponse { data } => {
                QuicFrameType::PathResponse.to_varint().encode_to_buf(buf)?;
                buf.put_slice(data);
            }

            QuicFrame::ConnectionClose {
                error_code,
                frame_type,
                reason_phrase,
            } => {
                if frame_type.is_some() {
                    QuicFrameType::ConnectionCloseQuic
                        .to_varint()
                        .encode_to_buf(buf)?;
                } else {
                    QuicFrameType::ConnectionCloseApp
                        .to_varint()
                        .encode_to_buf(buf)?;
                }

                error_code.encode_to_buf(buf)?;

                if let Some(ft) = frame_type {
                    ft.encode_to_buf(buf)?;
                }

                match VarInt::new(reason_phrase.len() as u64) {
                    Outcome::Ok(varint) => varint.encode_to_buf(buf)?,
                    _ => {
                        return Err(QuicFrameError::InvalidFormat(
                            "Invalid reason phrase length".to_string(),
                        ));
                    }
                }
                buf.put_slice(reason_phrase);
            }

            QuicFrame::HandshakeDone => {
                QuicFrameType::HandshakeDone
                    .to_varint()
                    .encode_to_buf(buf)?;
            }
        }

        Ok(())
    }

    /// Decode frame from buffer
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Option<Self>, QuicFrameError> {
        if !buf.has_remaining() {
            return Ok(None);
        }

        // Decode frame type
        let frame_type_varint = match VarInt::decode_from_buf(buf)? {
            Some(vint) => vint,
            None => return Ok(None),
        };

        let frame_type_value = frame_type_varint.value();

        // Handle frame type
        match frame_type_value {
            0x00 => {
                // PADDING - consume all consecutive padding bytes
                let mut length = 1; // We already consumed one 0x00
                while buf.has_remaining() && buf.chunk()[0] == 0x00 {
                    buf.advance(1);
                    length += 1;
                }
                Ok(Some(QuicFrame::Padding { length }))
            }

            0x01 => Ok(Some(QuicFrame::Ping)),

            0x02 | 0x03 => {
                // ACK frame (with or without ECN)
                let has_ecn = frame_type_value == 0x03;

                let largest_acknowledged =
                    VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                let ack_delay =
                    VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                let ack_range_count =
                    VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                let first_ack_range =
                    VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;

                let mut ack_ranges = Vec::new();
                for _ in 0..ack_range_count.value() {
                    let gap = VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                    let ack_range_length =
                        VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                    ack_ranges.push(AckRange {
                        gap,
                        ack_range_length,
                    });
                }

                let ecn_counts = if has_ecn {
                    let ect0_count =
                        VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                    let ect1_count =
                        VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                    let ecn_ce_count =
                        VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                    Some(EcnCounts {
                        ect0_count,
                        ect1_count,
                        ecn_ce_count,
                    })
                } else {
                    None
                };

                Ok(Some(QuicFrame::Ack {
                    largest_acknowledged,
                    ack_delay,
                    ack_range_count,
                    first_ack_range,
                    ack_ranges,
                    ecn_counts,
                }))
            }

            0x04 => {
                // RESET_STREAM
                let stream_id =
                    VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                let error_code =
                    VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                let final_size =
                    VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                Ok(Some(QuicFrame::ResetStream {
                    stream_id,
                    error_code,
                    final_size,
                }))
            }

            0x05 => {
                // STOP_SENDING
                let stream_id =
                    VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                let error_code =
                    VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                Ok(Some(QuicFrame::StopSending {
                    stream_id,
                    error_code,
                }))
            }

            0x06 => {
                // CRYPTO
                let offset = VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                let length = VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;

                if buf.remaining() < length.value() as usize {
                    return Err(QuicFrameError::UnexpectedEof);
                }

                let data = copy_to_bytes_from_buf(buf, length.value() as usize);
                Ok(Some(QuicFrame::Crypto { offset, data }))
            }

            ft if QuicFrameType::is_stream_frame(ft) => {
                // STREAM frame
                let has_off = (ft & 0x04) != 0;
                let has_len = (ft & 0x02) != 0;
                let fin = (ft & 0x01) != 0;

                let stream_id =
                    VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;

                let offset = if has_off {
                    Some(VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?)
                } else {
                    None
                };

                let data = if has_len {
                    let length =
                        VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                    if buf.remaining() < length.value() as usize {
                        return Err(QuicFrameError::UnexpectedEof);
                    }
                    copy_to_bytes_from_buf(buf, length.value() as usize)
                } else {
                    // Rest of packet
                    copy_to_bytes_from_buf(buf, buf.remaining())
                };

                Ok(Some(QuicFrame::Stream {
                    stream_id,
                    offset,
                    data,
                    fin,
                }))
            }

            0x10 => {
                // MAX_DATA
                let maximum_data =
                    VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                Ok(Some(QuicFrame::MaxData { maximum_data }))
            }

            0x11 => {
                // MAX_STREAM_DATA
                let stream_id =
                    VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                let maximum_stream_data =
                    VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                Ok(Some(QuicFrame::MaxStreamData {
                    stream_id,
                    maximum_stream_data,
                }))
            }

            0x12 => {
                // MAX_STREAMS (bidirectional)
                let maximum_streams =
                    VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                Ok(Some(QuicFrame::MaxStreams {
                    maximum_streams,
                    bidirectional: true,
                }))
            }

            0x13 => {
                // MAX_STREAMS (unidirectional)
                let maximum_streams =
                    VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                Ok(Some(QuicFrame::MaxStreams {
                    maximum_streams,
                    bidirectional: false,
                }))
            }

            0x14 => {
                // DATA_BLOCKED
                let maximum_data =
                    VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                Ok(Some(QuicFrame::DataBlocked { maximum_data }))
            }

            0x15 => {
                // STREAM_DATA_BLOCKED
                let stream_id =
                    VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                let maximum_stream_data =
                    VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                Ok(Some(QuicFrame::StreamDataBlocked {
                    stream_id,
                    maximum_stream_data,
                }))
            }

            0x16 => {
                // STREAMS_BLOCKED (bidirectional)
                let maximum_streams =
                    VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                Ok(Some(QuicFrame::StreamsBlocked {
                    maximum_streams,
                    bidirectional: true,
                }))
            }

            0x17 => {
                // STREAMS_BLOCKED (unidirectional)
                let maximum_streams =
                    VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                Ok(Some(QuicFrame::StreamsBlocked {
                    maximum_streams,
                    bidirectional: false,
                }))
            }

            0x1a => {
                // PATH_CHALLENGE
                if buf.remaining() < 8 {
                    return Err(QuicFrameError::UnexpectedEof);
                }
                let mut data = [0u8; 8];
                buf.copy_to_slice(&mut data);
                Ok(Some(QuicFrame::PathChallenge { data }))
            }

            0x1b => {
                // PATH_RESPONSE
                if buf.remaining() < 8 {
                    return Err(QuicFrameError::UnexpectedEof);
                }
                let mut data = [0u8; 8];
                buf.copy_to_slice(&mut data);
                Ok(Some(QuicFrame::PathResponse { data }))
            }

            0x1c => {
                // CONNECTION_CLOSE (QUIC)
                let error_code =
                    VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                let frame_type =
                    Some(VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?);
                let reason_length =
                    VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;

                if buf.remaining() < reason_length.value() as usize {
                    return Err(QuicFrameError::UnexpectedEof);
                }

                let reason_phrase = copy_to_bytes_from_buf(buf, reason_length.value() as usize);
                Ok(Some(QuicFrame::ConnectionClose {
                    error_code,
                    frame_type,
                    reason_phrase,
                }))
            }

            0x1d => {
                // CONNECTION_CLOSE (Application)
                let error_code =
                    VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;
                let reason_length =
                    VarInt::decode_from_buf(buf)?.ok_or(QuicFrameError::UnexpectedEof)?;

                if buf.remaining() < reason_length.value() as usize {
                    return Err(QuicFrameError::UnexpectedEof);
                }

                let reason_phrase = copy_to_bytes_from_buf(buf, reason_length.value() as usize);
                Ok(Some(QuicFrame::ConnectionClose {
                    error_code,
                    frame_type: None,
                    reason_phrase,
                }))
            }

            0x1e => {
                // HANDSHAKE_DONE
                Ok(Some(QuicFrame::HandshakeDone))
            }

            other => Err(QuicFrameError::UnknownFrameType(other)),
        }
    }
}

fn copy_to_bytes_from_buf<B: Buf>(buf: &mut B, len: usize) -> Bytes {
    let mut bytes = vec![0; len];
    buf.copy_to_slice(&mut bytes);
    Bytes::from(bytes)
}

/// Extensions for VarInt to work with Buf/BufMut
trait VarIntBufExt {
    fn encode_to_buf<B: BufMut>(&self, buf: &mut B) -> Result<(), QuicFrameError>;
    fn decode_from_buf<B: Buf>(buf: &mut B) -> Result<Option<VarInt>, QuicFrameError>;
}

impl VarIntBufExt for VarInt {
    fn encode_to_buf<B: BufMut>(&self, buf: &mut B) -> Result<(), QuicFrameError> {
        let mut temp = BytesMut::new();
        match self.encode(&mut temp) {
            Outcome::Ok(()) => {}
            _ => {
                return Err(QuicFrameError::InvalidFormat(
                    "VarInt encode failed".to_string(),
                ));
            }
        }
        buf.put_slice(&temp);
        Ok(())
    }

    fn decode_from_buf<B: Buf>(buf: &mut B) -> Result<Option<VarInt>, QuicFrameError> {
        let mut temp = BytesMut::new();
        temp.put_slice(&buf.chunk()[..buf.remaining().min(8)]); // VarInt is at most 8 bytes

        let original_len = temp.len();
        match VarInt::decode(&mut temp) {
            Outcome::Ok(Some(varint)) => {
                let consumed = original_len - temp.len();
                buf.advance(consumed);
                Ok(Some(varint))
            }
            Outcome::Ok(None) => Ok(None), // Need more data
            _ => Err(QuicFrameError::InvalidFormat(
                "Invalid varint encoding".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping_frame() {
        let frame = QuicFrame::Ping;
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let mut decode_buf = buf.freeze().reader();
        let decoded = QuicFrame::decode(&mut decode_buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_max_data_frame() {
        let frame = QuicFrame::MaxData {
            maximum_data: VarInt::new(1024).unwrap(),
        };
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let mut decode_buf = buf.freeze().reader();
        let decoded = QuicFrame::decode(&mut decode_buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_stream_frame_with_offset_and_length() {
        let frame = QuicFrame::Stream {
            stream_id: VarInt::new(4).unwrap(),
            offset: Some(VarInt::new(1000).unwrap()),
            data: Bytes::from_static(b"Hello, QUIC!"),
            fin: true,
        };
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let mut decode_buf = buf.freeze().reader();
        let decoded = QuicFrame::decode(&mut decode_buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_path_challenge_frame() {
        let frame = QuicFrame::PathChallenge {
            data: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let mut decode_buf = buf.freeze().reader();
        let decoded = QuicFrame::decode(&mut decode_buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_connection_close_quic() {
        let frame = QuicFrame::ConnectionClose {
            error_code: VarInt::new(10).unwrap(),
            frame_type: Some(VarInt::new(0x06).unwrap()), // CRYPTO frame
            reason_phrase: Bytes::from_static(b"Handshake failed"),
        };
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let mut decode_buf = buf.freeze().reader();
        let decoded = QuicFrame::decode(&mut decode_buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_ack_frame_simple() {
        let frame = QuicFrame::Ack {
            largest_acknowledged: VarInt::new(100).unwrap(),
            ack_delay: VarInt::new(50).unwrap(),
            ack_range_count: VarInt::new(0).unwrap(),
            first_ack_range: VarInt::new(10).unwrap(),
            ack_ranges: Vec::new(),
            ecn_counts: None,
        };
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let mut decode_buf = buf.freeze().reader();
        let decoded = QuicFrame::decode(&mut decode_buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_crypto_frame() {
        let frame = QuicFrame::Crypto {
            offset: VarInt::new(0).unwrap(),
            data: Bytes::from_static(b"TLS handshake data"),
        };
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let mut decode_buf = buf.freeze().reader();
        let decoded = QuicFrame::decode(&mut decode_buf).unwrap().unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_frame_type_parsing() {
        assert_eq!(
            QuicFrameType::from_varint(VarInt::new(0x01).unwrap()).unwrap(),
            QuicFrameType::Ping
        );
        assert_eq!(
            QuicFrameType::from_varint(VarInt::new(0x1a).unwrap()).unwrap(),
            QuicFrameType::PathChallenge
        );
        assert!(QuicFrameType::is_stream_frame(0x08));
        assert!(QuicFrameType::is_stream_frame(0x0f));
        assert!(!QuicFrameType::is_stream_frame(0x10));
    }
}
