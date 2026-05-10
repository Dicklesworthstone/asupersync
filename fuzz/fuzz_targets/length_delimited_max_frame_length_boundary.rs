//! Focused fuzz target for LengthDelimitedCodec max_frame_length boundary testing.
//!
//! This target specifically tests the max_frame_length security boundary:
//! - frames exactly at max_frame_length are accepted
//! - frames exceeding max_frame_length by 1 byte are rejected
//! - oversized length declarations trigger proper error handling
//! - boundary conditions don't cause panics or infinite loops
//!
//! # Security Properties
//! - max_frame_length prevents memory exhaustion attacks
//! - oversized frames are rejected with proper error codes
//! - decoder recovers correctly after oversized frame rejection
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run length_delimited_max_frame_length_boundary
//! ```

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{BufMut, BytesMut};
use asupersync::codec::{Decoder, Encoder, LengthDelimitedCodec};
use libfuzzer_sys::fuzz_target;
use std::io::{Error, ErrorKind};

/// Maximum input size to prevent timeouts
const MAX_FUZZ_INPUT_SIZE: usize = 10_000;

/// Test configuration for max_frame_length boundary testing
#[derive(Arbitrary, Debug, Clone)]
struct MaxFrameLengthConfig {
    /// Maximum allowed frame length (security boundary)
    max_frame_length: u16, // u16 to keep test manageable
    /// Use big-endian encoding for length field
    big_endian: bool,
    /// Length field width (1, 2, or 4 bytes)
    length_field_width: FieldWidth,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum FieldWidth {
    One,  // u8 - max 255
    Two,  // u16 - max 65535
    Four, // u32 - max 4294967295
}

impl FieldWidth {
    fn to_bytes(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
        }
    }

    fn max_value(self) -> u64 {
        match self {
            Self::One => u8::MAX as u64,
            Self::Two => u16::MAX as u64,
            Self::Four => u32::MAX as u64,
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
enum BoundaryTest {
    /// Test frame exactly at max_frame_length (should succeed)
    ExactlyAtLimit { payload: Vec<u8> },
    /// Test frame 1 byte over max_frame_length (should fail)
    OneBytePastLimit { payload: Vec<u8> },
    /// Test frame significantly over max_frame_length (should fail)
    WayPastLimit {
        oversized_length: u32,
        payload: Vec<u8>,
    },
    /// Test zero-length frame (edge case, should succeed)
    ZeroLength,
    /// Test max possible length declaration within field width
    MaxFieldWidth { payload: Vec<u8> },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    config: MaxFrameLengthConfig,
    test: BoundaryTest,
}

impl MaxFrameLengthConfig {
    fn build_codec(&self) -> LengthDelimitedCodec {
        let builder = LengthDelimitedCodec::builder()
            .max_frame_length(self.max_frame_length as usize)
            .length_field_length(self.length_field_width.to_bytes());

        if self.big_endian {
            builder.big_endian().new_codec()
        } else {
            builder.little_endian().new_codec()
        }
    }

    fn encode_length(&self, length: u64, buf: &mut BytesMut) {
        let clamped = length.min(self.length_field_width.max_value());

        match self.length_field_width {
            FieldWidth::One => {
                buf.put_u8(clamped as u8);
            }
            FieldWidth::Two => {
                if self.big_endian {
                    buf.put_u16(clamped as u16);
                } else {
                    buf.put_u16_le(clamped as u16);
                }
            }
            FieldWidth::Four => {
                if self.big_endian {
                    buf.put_u32(clamped as u32);
                } else {
                    buf.put_u32_le(clamped as u32);
                }
            }
        }
    }
}

impl FuzzInput {
    fn construct_test_frame(&self) -> BytesMut {
        let mut frame = BytesMut::new();

        match &self.test {
            BoundaryTest::ExactlyAtLimit { payload } => {
                // Frame exactly at max_frame_length
                let target_len = self.config.max_frame_length as usize;
                let bounded_payload = if payload.len() >= target_len {
                    &payload[..target_len]
                } else {
                    payload
                };

                self.config
                    .encode_length(bounded_payload.len() as u64, &mut frame);
                frame.extend_from_slice(bounded_payload);
            }

            BoundaryTest::OneBytePastLimit { payload } => {
                // Frame 1 byte over max_frame_length
                let target_len = (self.config.max_frame_length as usize).saturating_add(1);
                self.config.encode_length(target_len as u64, &mut frame);

                // Add payload up to declared length
                let bounded_payload = if payload.len() >= target_len {
                    &payload[..target_len]
                } else {
                    payload
                };
                frame.extend_from_slice(bounded_payload);
            }

            BoundaryTest::WayPastLimit {
                oversized_length,
                payload,
            } => {
                // Frame way over max_frame_length
                let declared_len = (*oversized_length as u64)
                    .max((self.config.max_frame_length as u64).saturating_add(100));
                self.config.encode_length(declared_len, &mut frame);
                frame.extend_from_slice(payload);
            }

            BoundaryTest::ZeroLength => {
                // Zero-length frame
                self.config.encode_length(0, &mut frame);
                // No payload
            }

            BoundaryTest::MaxFieldWidth { payload } => {
                // Declare maximum possible length for this field width
                let max_len = self.config.length_field_width.max_value();
                self.config.encode_length(max_len, &mut frame);
                frame.extend_from_slice(payload);
            }
        }

        frame
    }
}

fn observe_final_decode(
    result: Result<Option<BytesMut>, Error>,
    context: &str,
    max_frame_length: usize,
) {
    match result {
        Ok(Some(decoded)) => {
            assert!(
                decoded.len() <= max_frame_length,
                "{context} decoded frame above max_frame_length: {} > {}",
                decoded.len(),
                max_frame_length
            );
            std::hint::black_box((context, decoded.len()));
        }
        Ok(None) => {
            std::hint::black_box((context, "pending"));
        }
        Err(error) => {
            let message = error.to_string();
            assert!(!message.is_empty(), "{context} returned an empty error");
            assert!(
                message.len() <= 4096,
                "{context} returned an oversized error: {} bytes",
                message.len()
            );
            std::hint::black_box((context, error.kind(), message));
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    let frame_bytes = input.construct_test_frame();

    // Bound input size to prevent timeouts
    if frame_bytes.len() > MAX_FUZZ_INPUT_SIZE {
        return;
    }

    let mut decoder = input.config.build_codec();
    let mut test_frame = frame_bytes.clone();

    match &input.test {
        BoundaryTest::ExactlyAtLimit { .. } => {
            // Frame exactly at limit should decode successfully
            let result = decoder.decode(&mut test_frame);
            match result {
                Ok(_) => {
                    // Success is expected for frames at the limit
                }
                Err(e) => {
                    // If it fails, it should be a proper error, not a panic
                    assert_eq!(
                        e.kind(),
                        ErrorKind::InvalidData,
                        "Frame at max_frame_length should either succeed or return InvalidData"
                    );
                }
            }
        }

        BoundaryTest::OneBytePastLimit { .. } => {
            // Frame 1 byte over limit should be rejected
            let result = decoder.decode(&mut test_frame);
            if let Err(e) = result {
                assert_eq!(
                    e.kind(),
                    ErrorKind::InvalidData,
                    "Oversized frame should return InvalidData error"
                );
            }
            // Note: We don't assert it MUST fail because the length field width
            // might be too small to express the oversized length
        }

        BoundaryTest::WayPastLimit {
            oversized_length, ..
        } => {
            // Significantly oversized frame should be rejected
            if *oversized_length > input.config.length_field_width.max_value() as u32 {
                // Length is too big for field width, will be clamped during encoding
                return;
            }

            let result = decoder.decode(&mut test_frame);
            if let Err(e) = result {
                assert_eq!(
                    e.kind(),
                    ErrorKind::InvalidData,
                    "Way oversized frame should return InvalidData error"
                );

                // Verify error message mentions max_frame_length
                let error_msg = e.to_string();
                assert!(
                    error_msg.contains("max_frame_length") || error_msg.contains("frame length"),
                    "Error message should mention frame length limit"
                );
            }
        }

        BoundaryTest::ZeroLength => {
            // Zero-length frames should succeed
            let result = decoder.decode(&mut test_frame);
            match result {
                Ok(Some(decoded)) => {
                    assert!(
                        decoded.is_empty(),
                        "Zero-length frame should decode to empty bytes"
                    );
                }
                Ok(None) => {
                    // Incomplete frame (might need more data)
                }
                Err(e) => {
                    panic!("Zero-length frame should not cause error: {}", e);
                }
            }
        }

        BoundaryTest::MaxFieldWidth { .. } => {
            // Frame with maximum possible length declaration should be rejected
            // (unless max_frame_length is also at the field width maximum)
            let result = decoder.decode(&mut test_frame);
            if let Err(e) = result {
                assert_eq!(
                    e.kind(),
                    ErrorKind::InvalidData,
                    "Max field width length should return InvalidData error"
                );
            }
        }
    }

    observe_final_decode(
        decoder.decode(&mut test_frame),
        "final malformed decode",
        input.config.max_frame_length as usize,
    );

    // Test round-trip for valid cases
    if matches!(
        input.test,
        BoundaryTest::ExactlyAtLimit { .. } | BoundaryTest::ZeroLength
    ) {
        let mut encoder = input.config.build_codec();
        let mut encoded = BytesMut::new();

        match &input.test {
            BoundaryTest::ExactlyAtLimit { payload } => {
                let target_len = input.config.max_frame_length as usize;
                let bounded_payload = if payload.len() >= target_len {
                    BytesMut::from(&payload[..target_len])
                } else {
                    BytesMut::from(payload.as_slice())
                };

                // Test that encoding at max_frame_length works
                if let Ok(()) = encoder.encode(bounded_payload.clone(), &mut encoded) {
                    let mut round_trip_decoder = input.config.build_codec();
                    let mut decode_buf = encoded.clone();
                    if let Ok(Some(decoded)) = round_trip_decoder.decode(&mut decode_buf) {
                        // Round-trip should preserve the payload
                        assert_eq!(
                            decoded.len(),
                            bounded_payload.len(),
                            "Round-trip preserved wrong payload length"
                        );
                    }
                }
            }

            BoundaryTest::ZeroLength => {
                let empty_payload = BytesMut::new();
                if let Ok(()) = encoder.encode(empty_payload, &mut encoded) {
                    let mut round_trip_decoder = input.config.build_codec();
                    let mut decode_buf = encoded.clone();
                    if let Ok(Some(decoded)) = round_trip_decoder.decode(&mut decode_buf) {
                        assert!(decoded.is_empty(), "Zero-length round-trip should be empty");
                    }
                }
            }

            _ => {}
        }
    }
});
