//! Comprehensive fuzz target for length-delimited frame parsing.
//!
//! This target feeds malformed length-prefixed frames to the LengthDelimitedCodec
//! to assert critical security and robustness properties:
//!
//! 1. Oversized length fields are guarded by max_frame_length
//! 2. Truncated payloads return Incomplete, not panic
//! 3. LENGTH_FIELD_ADJUSTMENT edge cases (negative/overflow)
//! 4. Variable-width length fields (u8/u16/u32/u64) correctly decoded
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run length_delimited
//! ```
//!
//! # Target Properties
//! - Structure-aware: generates valid frame headers with malformed payloads
//! - Security-focused: tests length field integer overflow/underflow
//! - Robustness: validates incomplete frame handling
//! - Performance: bounds input size to prevent timeout

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{BufMut, BytesMut};
use asupersync::codec::{Decoder, Encoder, LengthDelimitedCodec};
use libfuzzer_sys::fuzz_target;
use std::io::ErrorKind;

/// Maximum fuzz input size to prevent timeouts
const MAX_FUZZ_INPUT_SIZE: usize = 100_000;

/// Maximum frame payload size for practical testing
const MAX_FRAME_PAYLOAD_SIZE: usize = 10_000;

/// Length field width configuration for variable-width testing
#[derive(Arbitrary, Debug, Clone)]
enum LengthFieldWidth {
    U8,  // 1 byte
    U16, // 2 bytes
    U24, // 3 bytes (non-standard)
    U32, // 4 bytes
    U40, // 5 bytes (non-standard)
    U48, // 6 bytes (non-standard)
    U56, // 7 bytes (non-standard)
    U64, // 8 bytes
}

impl LengthFieldWidth {
    fn to_bytes(&self) -> usize {
        match self {
            Self::U8 => 1,
            Self::U16 => 2,
            Self::U24 => 3,
            Self::U32 => 4,
            Self::U40 => 5,
            Self::U48 => 6,
            Self::U56 => 7,
            Self::U64 => 8,
        }
    }

    /// Maximum value that can be represented in this width
    fn max_value(&self) -> u64 {
        match self {
            Self::U8 => u8::MAX as u64,
            Self::U16 => u16::MAX as u64,
            Self::U24 => 0xFF_FFFF,
            Self::U32 => u32::MAX as u64,
            Self::U40 => 0xFF_FFFF_FFFF,
            Self::U48 => 0xFF_FFFF_FFFF_FFFF,
            Self::U56 => 0xFFFF_FFFF_FFFF_FFFF,
            Self::U64 => u64::MAX,
        }
    }
}

/// Fuzz configuration covering all codec parameters
#[derive(Arbitrary, Debug, Clone)]
struct FuzzConfig {
    /// Offset to length field in frame header
    length_field_offset: u8, // 0-255
    /// Width of length field (variable width testing)
    length_field_width: LengthFieldWidth,
    /// Adjustment applied to length value (overflow/underflow testing)
    length_adjustment: i32, // Full range for overflow testing
    /// Bytes to skip after reading length
    num_skip: u8, // 0-255
    /// Maximum allowed frame length (security boundary)
    max_frame_length: u32, // Full range for boundary testing
    /// Byte order for multi-byte length fields
    big_endian: bool,
}

impl FuzzConfig {
    /// Build a LengthDelimitedCodec from this fuzz configuration
    fn build_codec(&self) -> Result<LengthDelimitedCodec, String> {
        let builder = LengthDelimitedCodec::builder()
            .length_field_offset(self.length_field_offset as usize)
            .length_field_length(self.length_field_width.to_bytes())
            .length_adjustment(self.length_adjustment as isize)
            .num_skip(self.num_skip as usize)
            .max_frame_length(self.max_frame_length as usize);

        let builder = if self.big_endian {
            builder.big_endian()
        } else {
            builder.little_endian()
        };

        Ok(builder.new_codec())
    }
}

/// Fuzz operation types for comprehensive coverage
#[derive(Arbitrary, Debug, Clone)]
enum FuzzOperation {
    /// Test oversized length field (security boundary)
    OversizedLength {
        /// Length value exceeding max_frame_length
        oversized_value: u64,
        /// Additional payload bytes
        payload: Vec<u8>,
    },
    /// Test truncated payload (incomplete frame handling)
    TruncatedPayload {
        /// Valid length field value
        length_value: u32,
        /// Payload shorter than declared length
        payload: Vec<u8>,
    },
    /// Test length adjustment edge cases
    LengthAdjustmentEdgeCase {
        /// Base length value
        base_length: u32,
        /// Payload that exercises adjustment boundary
        payload: Vec<u8>,
    },
    /// Test variable-width length field decoding
    VariableWidthLength {
        /// Length value within field width constraints
        length_value: u64,
        /// Payload data
        payload: Vec<u8>,
    },
    /// Test malformed frame headers
    MalformedHeader {
        /// Raw header bytes (potentially invalid)
        header_bytes: Vec<u8>,
        /// Payload data
        payload: Vec<u8>,
    },
    /// Test boundary conditions
    BoundaryCondition {
        /// Length exactly at max_frame_length
        at_boundary: bool,
        /// Payload data
        payload: Vec<u8>,
    },
}

/// Complete fuzz input combining configuration and operation
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Codec configuration
    config: FuzzConfig,
    /// Fuzz operation to execute
    operation: FuzzOperation,
}

impl FuzzInput {
    /// Construct malformed frame bytes based on operation and config
    fn construct_frame_bytes(&self) -> BytesMut {
        let mut frame = BytesMut::new();

        match &self.operation {
            FuzzOperation::OversizedLength {
                oversized_value,
                payload,
            } => {
                self.write_header(&mut frame, *oversized_value);
                frame.extend_from_slice(payload);
            }
            FuzzOperation::TruncatedPayload {
                length_value,
                payload,
            } => {
                self.write_header(&mut frame, *length_value as u64);
                // Write only part of the declared payload
                let truncated_len = payload.len().min(*length_value as usize / 2);
                frame.extend_from_slice(&payload[..truncated_len]);
            }
            FuzzOperation::LengthAdjustmentEdgeCase {
                base_length,
                payload,
            } => {
                // Test edge cases around length adjustment
                self.write_header(&mut frame, *base_length as u64);
                frame.extend_from_slice(payload);
            }
            FuzzOperation::VariableWidthLength {
                length_value,
                payload,
            } => {
                // Clamp length_value to field width maximum
                let clamped = (*length_value).min(self.config.length_field_width.max_value());
                self.write_header(&mut frame, clamped);
                frame.extend_from_slice(payload);
            }
            FuzzOperation::MalformedHeader {
                header_bytes,
                payload,
            } => {
                // Write potentially malformed header directly
                frame.extend_from_slice(header_bytes);
                frame.extend_from_slice(payload);
            }
            FuzzOperation::BoundaryCondition {
                at_boundary,
                payload,
            } => {
                let length = if *at_boundary {
                    self.config.max_frame_length as u64
                } else {
                    (self.config.max_frame_length / 2) as u64
                };
                self.write_header(&mut frame, length);
                frame.extend_from_slice(payload);
            }
        }

        frame
    }

    /// Write frame header with length field according to configuration
    fn write_header(&self, frame: &mut BytesMut, length_value: u64) {
        // Write length field offset padding
        for _ in 0..self.config.length_field_offset {
            frame.put_u8(0x00);
        }

        // Write length field in configured width and endianness
        self.write_length_field(frame, length_value);
    }

    /// Write length field value in specified width and byte order
    fn write_length_field(&self, frame: &mut BytesMut, mut value: u64) {
        // Clamp to field width maximum to prevent overflow
        value = value.min(self.config.length_field_width.max_value());

        let width = self.config.length_field_width.to_bytes();

        if self.config.big_endian {
            // Big-endian: most significant byte first
            match width {
                1 => frame.put_u8(value as u8),
                2 => frame.put_u16(value as u16),
                3 => {
                    frame.put_u8((value >> 16) as u8);
                    frame.put_u16(value as u16);
                }
                4 => frame.put_u32(value as u32),
                5 => {
                    frame.put_u8((value >> 32) as u8);
                    frame.put_u32(value as u32);
                }
                6 => {
                    frame.put_u16((value >> 32) as u16);
                    frame.put_u32(value as u32);
                }
                7 => {
                    frame.put_u8((value >> 48) as u8);
                    frame.put_u16((value >> 32) as u16);
                    frame.put_u32(value as u32);
                }
                8 => frame.put_u64(value),
                _ => unreachable!("Invalid width"),
            }
        } else {
            // Little-endian: least significant byte first
            match width {
                1 => frame.put_u8(value as u8),
                2 => frame.put_u16_le(value as u16),
                3 => {
                    frame.put_u16_le(value as u16);
                    frame.put_u8((value >> 16) as u8);
                }
                4 => frame.put_u32_le(value as u32),
                5 => {
                    frame.put_u32_le(value as u32);
                    frame.put_u8((value >> 32) as u8);
                }
                6 => {
                    frame.put_u32_le(value as u32);
                    frame.put_u16_le((value >> 32) as u16);
                }
                7 => {
                    frame.put_u32_le(value as u32);
                    frame.put_u16_le((value >> 32) as u16);
                    frame.put_u8((value >> 48) as u8);
                }
                8 => frame.put_u64_le(value),
                _ => unreachable!("Invalid width"),
            }
        }
    }
}

fn operation_payload(operation: &FuzzOperation) -> &[u8] {
    match operation {
        FuzzOperation::OversizedLength { payload, .. }
        | FuzzOperation::TruncatedPayload { payload, .. }
        | FuzzOperation::LengthAdjustmentEdgeCase { payload, .. }
        | FuzzOperation::VariableWidthLength { payload, .. }
        | FuzzOperation::MalformedHeader { payload, .. }
        | FuzzOperation::BoundaryCondition { payload, .. } => payload,
    }
}

fn header_len(config: &FuzzConfig) -> usize {
    usize::from(config.length_field_offset) + config.length_field_width.to_bytes()
}

fn normalized_roundtrip_case(input: &FuzzInput) -> (FuzzConfig, BytesMut) {
    let mut config = input.config.clone();
    config.length_adjustment = config.length_adjustment.clamp(-64, 64);

    let negative_adjustment = if config.length_adjustment < 0 {
        (-config.length_adjustment) as usize
    } else {
        0
    };
    let positive_adjustment = if config.length_adjustment > 0 {
        config.length_adjustment as usize
    } else {
        0
    };

    let width_cap = config.length_field_width.max_value().min(usize::MAX as u64) as usize;
    let max_payload = width_cap
        .saturating_sub(negative_adjustment)
        .min(MAX_FRAME_PAYLOAD_SIZE);
    let source = operation_payload(&input.operation);
    let target_len = source
        .len()
        .min(max_payload)
        .max(positive_adjustment.min(max_payload));

    let mut payload = source[..source.len().min(target_len)].to_vec();
    payload.resize(target_len, 0);

    config.max_frame_length = config.max_frame_length.max(target_len as u32);
    let total_frame_len = header_len(&config).saturating_add(target_len);
    config.num_skip = usize::from(config.num_skip).min(total_frame_len) as u8;

    (config, BytesMut::from(&payload[..]))
}

fn build_declared_frame(config: &FuzzConfig, declared_len: u64) -> BytesMut {
    let mut frame = BytesMut::new();
    for _ in 0..config.length_field_offset {
        frame.put_u8(0);
    }

    let width = config.length_field_width.to_bytes();
    let value = declared_len.min(config.length_field_width.max_value());
    if config.big_endian {
        match width {
            1 => frame.put_u8(value as u8),
            2 => frame.put_u16(value as u16),
            3 => {
                frame.put_u8((value >> 16) as u8);
                frame.put_u16(value as u16);
            }
            4 => frame.put_u32(value as u32),
            5 => {
                frame.put_u8((value >> 32) as u8);
                frame.put_u32(value as u32);
            }
            6 => {
                frame.put_u16((value >> 32) as u16);
                frame.put_u32(value as u32);
            }
            7 => {
                frame.put_u8((value >> 48) as u8);
                frame.put_u16((value >> 32) as u16);
                frame.put_u32(value as u32);
            }
            8 => frame.put_u64(value),
            _ => unreachable!("Invalid width"),
        }
    } else {
        match width {
            1 => frame.put_u8(value as u8),
            2 => frame.put_u16_le(value as u16),
            3 => {
                frame.put_u16_le(value as u16);
                frame.put_u8((value >> 16) as u8);
            }
            4 => frame.put_u32_le(value as u32),
            5 => {
                frame.put_u32_le(value as u32);
                frame.put_u8((value >> 32) as u8);
            }
            6 => {
                frame.put_u32_le(value as u32);
                frame.put_u16_le((value >> 32) as u16);
            }
            7 => {
                frame.put_u32_le(value as u32);
                frame.put_u16_le((value >> 32) as u16);
                frame.put_u8((value >> 48) as u8);
            }
            8 => frame.put_u64_le(value),
            _ => unreachable!("Invalid width"),
        }
    }

    frame
}

fn encode_frame(config: &FuzzConfig, payload: &[u8]) -> BytesMut {
    let mut encoder = config.build_codec().expect("edge-case config should build");
    let mut wire = BytesMut::new();
    encoder
        .encode(BytesMut::from(payload), &mut wire)
        .expect("edge-case payload should encode");
    wire
}

fn visible_frame_bytes(config: &FuzzConfig, wire: &BytesMut) -> BytesMut {
    BytesMut::from(&wire[usize::from(config.num_skip)..])
}

fn bounded_payload(source: &[u8], target_len: usize) -> BytesMut {
    let mut payload = source[..source.len().min(target_len)].to_vec();
    payload.resize(target_len, 0xA5);
    BytesMut::from(&payload[..])
}

fn normalized_edge_case_config(base: &FuzzConfig, payload_len: usize) -> FuzzConfig {
    let mut config = base.clone();
    config.length_adjustment = 0;
    config.max_frame_length = config
        .max_frame_length
        .max(u32::try_from(payload_len).expect("payload_len bounded by fuzz target"));
    let total_frame_len = header_len(&config).saturating_add(payload_len);
    config.num_skip = usize::from(config.num_skip)
        .min(total_frame_len)
        .min(u8::MAX as usize) as u8;
    config
}

fuzz_target!(|input: FuzzInput| {
    let frame_bytes = input.construct_frame_bytes();
    if frame_bytes.len() > MAX_FUZZ_INPUT_SIZE {
        return;
    }

    let mut codec = match input.config.build_codec() {
        Ok(codec) => codec,
        Err(_) => return,
    };
    let mut stress_frame = frame_bytes.clone();
    let _ = codec.decode(&mut stress_frame);

    let (roundtrip_config, roundtrip_payload) = normalized_roundtrip_case(&input);

    let mut roundtrip_encoder = roundtrip_config
        .build_codec()
        .expect("normalized config should build");
    let mut roundtrip_wire = BytesMut::new();
    roundtrip_encoder
        .encode(roundtrip_payload.clone(), &mut roundtrip_wire)
        .expect("normalized payload should encode");

    let expected = BytesMut::from(&roundtrip_wire[usize::from(roundtrip_config.num_skip)..]);
    let mut roundtrip_decoder = roundtrip_config
        .build_codec()
        .expect("normalized config should build");
    let mut roundtrip_buf = roundtrip_wire.clone();
    let decoded = roundtrip_decoder
        .decode(&mut roundtrip_buf)
        .expect("round-trip decode must not error")
        .expect("round-trip frame must decode");
    assert_eq!(decoded, expected, "round-trip retained bytes diverged");
    assert!(roundtrip_buf.is_empty(), "round-trip left unread bytes");

    let mut partial_decoder = roundtrip_config
        .build_codec()
        .expect("normalized config should build");
    let split_at = roundtrip_wire.len().saturating_sub(1);
    let mut partial_buf = BytesMut::from(&roundtrip_wire[..split_at]);
    assert!(
        partial_decoder
            .decode(&mut partial_buf)
            .expect("partial frame must not error")
            .is_none(),
        "partial frame decoded before the final byte arrived"
    );

    let mut second_encoder = roundtrip_config
        .build_codec()
        .expect("normalized config should build");
    let mut second_wire = BytesMut::new();
    second_encoder
        .encode(roundtrip_payload.clone(), &mut second_wire)
        .expect("second frame should encode");
    let second_prefix_len = second_wire
        .len()
        .saturating_sub(1)
        .min(header_len(&roundtrip_config).saturating_sub(1));

    partial_buf.extend_from_slice(&roundtrip_wire[split_at..]);
    partial_buf.extend_from_slice(&second_wire[..second_prefix_len]);
    let decoded = partial_decoder
        .decode(&mut partial_buf)
        .expect("completed frame must not error")
        .expect("completed frame should decode");
    assert_eq!(decoded, expected, "completed frame decoded incorrectly");
    assert!(
        partial_decoder
            .decode(&mut partial_buf)
            .expect("partial second frame must not error")
            .is_none(),
        "incomplete second frame unexpectedly decoded"
    );
    assert_eq!(
        &partial_buf[..],
        &second_wire[..second_prefix_len],
        "decoder retained the wrong second-frame prefix"
    );

    let edge_source = operation_payload(&input.operation);

    let zero_config = normalized_edge_case_config(&roundtrip_config, 0);
    let zero_wire = encode_frame(&zero_config, &[]);
    let zero_expected = visible_frame_bytes(&zero_config, &zero_wire);
    let mut zero_decoder = zero_config
        .build_codec()
        .expect("zero-length config should build");
    let mut zero_buf = zero_wire.clone();
    let zero_decoded = zero_decoder
        .decode(&mut zero_buf)
        .expect("zero-length frame must not error")
        .expect("zero-length frame should decode");
    assert_eq!(
        zero_decoded, zero_expected,
        "zero-length frame retained the wrong visible bytes"
    );
    assert!(
        zero_buf.is_empty(),
        "zero-length decode left unread bytes behind"
    );

    let exact_max_len = roundtrip_config
        .length_field_width
        .max_value()
        .min(usize::MAX as u64);
    let exact_max_len = (exact_max_len as usize)
        .min(MAX_FRAME_PAYLOAD_SIZE)
        .clamp(1, 256);
    let mut exact_max_config = normalized_edge_case_config(&roundtrip_config, exact_max_len);
    exact_max_config.max_frame_length =
        u32::try_from(exact_max_len).expect("exact_max_len bounded by fuzz target");
    let exact_max_payload = bounded_payload(edge_source, exact_max_len);
    let exact_max_wire = encode_frame(&exact_max_config, &exact_max_payload);
    let exact_max_expected = visible_frame_bytes(&exact_max_config, &exact_max_wire);
    let mut exact_max_decoder = exact_max_config
        .build_codec()
        .expect("exact-max config should build");
    let mut exact_max_buf = exact_max_wire.clone();
    let exact_max_decoded = exact_max_decoder
        .decode(&mut exact_max_buf)
        .expect("exact-max frame must not error")
        .expect("exact-max frame should decode");
    assert_eq!(
        exact_max_decoded, exact_max_expected,
        "exact-max frame retained the wrong visible bytes"
    );
    assert!(
        exact_max_buf.is_empty(),
        "exact-max decode left unread bytes behind"
    );

    let partial_len = exact_max_len.clamp(1, 32);
    let mut partial_config = normalized_edge_case_config(&roundtrip_config, partial_len);
    partial_config.max_frame_length =
        u32::try_from(partial_len).expect("partial_len bounded by fuzz target");
    let partial_payload = bounded_payload(edge_source, partial_len);
    let partial_wire = encode_frame(&partial_config, &partial_payload);
    let partial_expected = visible_frame_bytes(&partial_config, &partial_wire);
    let mut partial_decoder = partial_config
        .build_codec()
        .expect("bytewise partial config should build");
    let mut partial_stream = BytesMut::new();
    for (index, byte) in partial_wire.iter().enumerate() {
        partial_stream.extend_from_slice(std::slice::from_ref(byte));
        let decoded = partial_decoder
            .decode(&mut partial_stream)
            .expect("bytewise partial frame must not error");
        if index + 1 == partial_wire.len() {
            assert_eq!(
                decoded.expect("bytewise partial frame should finish on the last byte"),
                partial_expected.clone(),
                "bytewise partial decode retained the wrong visible bytes"
            );
        } else {
            assert!(
                decoded.is_none(),
                "bytewise partial frame decoded early at byte {}",
                index + 1
            );
        }
    }
    assert!(
        partial_stream.is_empty(),
        "bytewise partial decode left unread bytes behind"
    );

    let mut max_config = input.config.clone();
    max_config.length_adjustment = 0;
    let width_cap = max_config
        .length_field_width
        .max_value()
        .min(usize::MAX as u64) as usize;
    let max_frame_cap = width_cap
        .saturating_sub(1)
        .min(MAX_FRAME_PAYLOAD_SIZE.saturating_sub(1));
    max_config.max_frame_length = max_frame_cap as u32;
    max_config.num_skip = u8::try_from(header_len(&max_config)).unwrap_or(u8::MAX);

    let mut oversized_frame =
        build_declared_frame(&max_config, u64::from(max_config.max_frame_length) + 1);
    let mut max_decoder = max_config
        .build_codec()
        .expect("max-frame config should build");
    let err = max_decoder
        .decode(&mut oversized_frame)
        .expect_err("oversized declared frame must error");
    assert_eq!(
        err.kind(),
        ErrorKind::InvalidData,
        "oversized decode should return InvalidData"
    );

    let oversized_payload = BytesMut::from(&vec![0u8; max_frame_cap.saturating_add(1)][..]);
    let mut max_encoder = max_config
        .build_codec()
        .expect("max-frame config should build");
    let mut encoded = BytesMut::new();
    let err = max_encoder
        .encode(oversized_payload, &mut encoded)
        .expect_err("oversized payload must fail encode");
    assert_eq!(
        err.kind(),
        ErrorKind::InvalidData,
        "oversized encode should return InvalidData"
    );
});
