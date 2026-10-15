#![no_main]

//! Fuzz target: HTTP/2 DATA frame payload at SETTINGS_MAX_FRAME_SIZE boundary
//!
//! Tests DATA frames with payload sizes exactly equal to SETTINGS_MAX_FRAME_SIZE.
//! Per RFC 7540 §6.5.2, frames at the maximum size should be ACCEPTED (boundary
//! condition, not an error). Tests various MAX_FRAME_SIZE values and validates
//! proper boundary handling.
//!
//! Key behaviors tested:
//! - DATA frames with payload = MAX_FRAME_SIZE are accepted
//! - DATA frames with payload > MAX_FRAME_SIZE are rejected
//! - Proper handling of different MAX_FRAME_SIZE settings (16384..16777215)
//! - Boundary testing around the configured limits
//! - Frame parsing with exact size matches

use arbitrary::Arbitrary;
use asupersync::bytes::{BufMut, BytesMut};
use asupersync::codec::Decoder;
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::{
    DEFAULT_MAX_FRAME_SIZE, FrameHeader, FrameType, MAX_FRAME_SIZE, MIN_MAX_FRAME_SIZE, Setting,
    data_flags,
};
use asupersync::http::h2::{Frame, FrameCodec, H2Error, Settings};
use libfuzzer_sys::fuzz_target;

const SETTINGS_MAX_FRAME_SIZE_ID: u16 = 0x5;
const MAX_FUZZ_CASES: usize = 32;
const MAX_GENERATED_FRAME_PAYLOAD: u32 = 64 * 1024;

#[derive(Debug)]
struct LiveH2DataFrameDecoder {
    codec: FrameCodec,
    settings: Settings,
}

#[derive(Debug, PartialEq, Eq)]
enum ParseResult {
    SettingsProcessed {
        max_frame_size: u32,
    },
    DataFrameProcessed {
        stream_id: u32,
        payload_size: u32,
        data_len: usize,
        end_stream: bool,
    },
    FrameSizeError,
    ProtocolError(ErrorCode),
    FrameProcessed,
    SkippedLargeAcceptedCandidate {
        payload_size: u32,
        max_frame_size: u32,
    },
    InvalidWireLength {
        payload_size: Option<u32>,
    },
    PendingIncomplete,
}

/// Input for fuzz testing
#[derive(Debug, Arbitrary)]
struct H2DataPayloadMaxInput {
    /// Initial MAX_FRAME_SIZE setting (None = use default)
    initial_max_frame_size: Option<u32>,

    /// Test cases to execute
    test_cases: Vec<FrameSizeTest>,
}

#[derive(Debug, Arbitrary)]
struct FrameSizeTest {
    /// The payload size to test
    payload_size: u32,

    /// Stream ID for the DATA frame (must be > 0)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(1..=u32::MAX))]
    stream_id: u32,

    /// Whether to use the PADDED flag
    padded: bool,

    /// Padding size if padded (0..255)
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| u.int_in_range(0..=255))]
    padding_size: u8,

    /// Whether to set END_STREAM flag
    end_stream: bool,

    /// Update MAX_FRAME_SIZE before this test (None = no update)
    update_max_frame_size: Option<u32>,
}

impl LiveH2DataFrameDecoder {
    fn new() -> Self {
        let settings = Settings::default();
        let mut codec = FrameCodec::new();
        codec.set_max_frame_size(settings.max_frame_size);
        Self { codec, settings }
    }

    fn process_settings(&mut self, settings: &[(u16, u32)]) -> ParseResult {
        let mut wire = encode_settings_frame(settings);
        match self.codec.decode(&mut wire) {
            Ok(Some(Frame::Settings(frame))) => {
                let mut changed_max_frame_size = false;
                for setting in frame.settings {
                    changed_max_frame_size |= matches!(setting, Setting::MaxFrameSize(_));
                    if let Err(err) = self.settings.apply(setting) {
                        return ParseResult::from_error(err);
                    }
                }

                self.codec.set_max_frame_size(self.settings.max_frame_size);
                if changed_max_frame_size {
                    ParseResult::SettingsProcessed {
                        max_frame_size: self.settings.max_frame_size,
                    }
                } else {
                    ParseResult::FrameProcessed
                }
            }
            Ok(Some(other)) => panic!("encoded SETTINGS decoded as {other:?}"),
            Ok(None) => ParseResult::PendingIncomplete,
            Err(err) => ParseResult::from_error(err),
        }
    }

    fn process_data_frame(
        &mut self,
        stream_id: u32,
        payload_size: u32,
        padded: bool,
        padding_size: u8,
        end_stream: bool,
    ) -> ParseResult {
        let Some(total_payload_size) =
            declared_data_payload_size(payload_size, padded, padding_size)
        else {
            return ParseResult::InvalidWireLength { payload_size: None };
        };

        if total_payload_size > MAX_FRAME_SIZE {
            return ParseResult::InvalidWireLength {
                payload_size: Some(total_payload_size),
            };
        }

        if total_payload_size <= self.settings.max_frame_size
            && total_payload_size > MAX_GENERATED_FRAME_PAYLOAD
        {
            return ParseResult::SkippedLargeAcceptedCandidate {
                payload_size: total_payload_size,
                max_frame_size: self.settings.max_frame_size,
            };
        }

        let include_payload = total_payload_size <= self.settings.max_frame_size;
        let mut wire = encode_data_frame(
            stream_id,
            payload_size,
            padded,
            padding_size,
            end_stream,
            include_payload,
        );

        match self.codec.decode(&mut wire) {
            Ok(Some(Frame::Data(frame))) => ParseResult::DataFrameProcessed {
                stream_id: frame.stream_id,
                payload_size: total_payload_size,
                data_len: frame.data.len(),
                end_stream: frame.end_stream,
            },
            Ok(Some(other)) => panic!("encoded DATA decoded as {other:?}"),
            Ok(None) => ParseResult::PendingIncomplete,
            Err(err) => ParseResult::from_error(err),
        }
    }
}

impl ParseResult {
    fn from_error(err: H2Error) -> Self {
        match err.code {
            ErrorCode::FrameSizeError => Self::FrameSizeError,
            code => Self::ProtocolError(code),
        }
    }
}

fn declared_data_payload_size(payload_size: u32, padded: bool, padding_size: u8) -> Option<u32> {
    if padded {
        1u32.checked_add(payload_size)?
            .checked_add(u32::from(padding_size))
    } else {
        Some(payload_size)
    }
}

fn encode_data_frame(
    stream_id: u32,
    payload_size: u32,
    padded: bool,
    padding_size: u8,
    end_stream: bool,
    include_payload: bool,
) -> BytesMut {
    let total_payload_len = declared_data_payload_size(payload_size, padded, padding_size)
        .expect("DATA frame payload length must fit u32 before constructing wire bytes");

    let mut frame = BytesMut::new();
    let mut flags = 0u8;
    if end_stream {
        flags |= data_flags::END_STREAM;
    }
    if padded {
        flags |= data_flags::PADDED;
    }

    write_frame_header(
        total_payload_len,
        FrameType::Data as u8,
        flags,
        stream_id,
        &mut frame,
    );

    if !include_payload {
        return frame;
    }

    if padded {
        frame.put_u8(padding_size);
    }
    frame.resize(frame.len() + payload_size as usize, 0x42);
    if padded {
        frame.resize(frame.len() + usize::from(padding_size), 0);
    }

    frame
}

fn encode_settings_frame(settings: &[(u16, u32)]) -> BytesMut {
    let mut frame = BytesMut::new();
    let payload_len =
        u32::try_from(settings.len() * 6).expect("SETTINGS fuzz payload length must fit u32");
    write_frame_header(payload_len, FrameType::Settings as u8, 0, 0, &mut frame);
    for &(setting_id, value) in settings {
        frame.put_u16(setting_id);
        frame.put_u32(value);
    }
    frame
}

fn process_input(input: &H2DataPayloadMaxInput) -> Vec<ParseResult> {
    let mut decoder = LiveH2DataFrameDecoder::new();
    let mut results = Vec::new();

    if let Some(initial_size) = input.initial_max_frame_size {
        results.push(decoder.process_settings(&[(SETTINGS_MAX_FRAME_SIZE_ID, initial_size)]));
    }

    for test in input.test_cases.iter().take(MAX_FUZZ_CASES) {
        if let Some(new_size) = test.update_max_frame_size {
            results.push(decoder.process_settings(&[(SETTINGS_MAX_FRAME_SIZE_ID, new_size)]));
        }
        results.push(decoder.process_data_frame(
            test.stream_id,
            test.payload_size,
            test.padded,
            test.padding_size,
            test.end_stream,
        ));
    }

    results
}

fn write_frame_header(length: u32, frame_type: u8, flags: u8, stream_id: u32, dst: &mut BytesMut) {
    FrameHeader {
        length,
        frame_type,
        flags,
        stream_id,
    }
    .write(dst);
}

fuzz_target!(|input: H2DataPayloadMaxInput| {
    if input.test_cases.is_empty() {
        return;
    }

    let results = process_input(&input);
    assert_input_invariants(&input, &results);
    exercise_boundary_conditions();
    exercise_padded_boundary_conditions();
});

fn assert_input_invariants(input: &H2DataPayloadMaxInput, results: &[ParseResult]) {
    let mut current_max_frame_size = DEFAULT_MAX_FRAME_SIZE;
    let mut result_index = 0;

    if input.initial_max_frame_size.is_some() {
        update_expected_max_frame_size(&mut current_max_frame_size, &results[result_index]);
        result_index += 1;
    }

    for test in input.test_cases.iter().take(MAX_FUZZ_CASES) {
        if test.update_max_frame_size.is_some() {
            update_expected_max_frame_size(&mut current_max_frame_size, &results[result_index]);
            result_index += 1;
        }

        let result = &results[result_index];
        result_index += 1;

        let total_payload_size =
            declared_data_payload_size(test.payload_size, test.padded, test.padding_size);
        assert_data_result_invariant(
            result,
            total_payload_size,
            current_max_frame_size,
            test.stream_id,
            test.payload_size,
            test.end_stream,
        );
    }
}

fn update_expected_max_frame_size(current: &mut u32, result: &ParseResult) {
    if let ParseResult::SettingsProcessed { max_frame_size } = result {
        *current = *max_frame_size;
    }
}

fn assert_data_result_invariant(
    result: &ParseResult,
    total_payload_size: Option<u32>,
    current_max_frame_size: u32,
    stream_id: u32,
    data_len: u32,
    end_stream: bool,
) {
    match result {
        ParseResult::DataFrameProcessed {
            stream_id: decoded_stream_id,
            payload_size,
            data_len: decoded_data_len,
            end_stream: decoded_end_stream,
        } => {
            let expected_payload_size =
                total_payload_size.expect("decoded DATA frame must have a representable length");
            assert!(
                expected_payload_size <= current_max_frame_size,
                "live codec accepted frame {expected_payload_size} bytes above MAX_FRAME_SIZE {current_max_frame_size}"
            );
            assert_eq!(*decoded_stream_id, stream_id & 0x7fff_ffff);
            assert_eq!(*payload_size, expected_payload_size);
            assert_eq!(*decoded_data_len, data_len as usize);
            assert_eq!(*decoded_end_stream, end_stream);
        }
        ParseResult::FrameSizeError => {
            let expected_payload_size =
                total_payload_size.expect("frame-size errors require a representable length");
            assert!(
                expected_payload_size > current_max_frame_size,
                "live codec rejected frame {expected_payload_size} bytes at or below MAX_FRAME_SIZE {current_max_frame_size}"
            );
        }
        ParseResult::SkippedLargeAcceptedCandidate {
            payload_size,
            max_frame_size,
        } => {
            assert!(*payload_size <= *max_frame_size);
            assert!(*payload_size > MAX_GENERATED_FRAME_PAYLOAD);
        }
        ParseResult::InvalidWireLength { payload_size } => {
            if let Some(payload_size) = payload_size {
                assert!(*payload_size > MAX_FRAME_SIZE);
            } else {
                assert!(total_payload_size.is_none());
            }
        }
        ParseResult::ProtocolError(_) => {}
        ParseResult::PendingIncomplete
        | ParseResult::SettingsProcessed { .. }
        | ParseResult::FrameProcessed => panic!("unexpected DATA result: {result:?}"),
    }
}

fn exercise_boundary_conditions() {
    let boundary_tests = [
        (DEFAULT_MAX_FRAME_SIZE, DEFAULT_MAX_FRAME_SIZE, true),
        (DEFAULT_MAX_FRAME_SIZE, DEFAULT_MAX_FRAME_SIZE - 1, true),
        (DEFAULT_MAX_FRAME_SIZE, DEFAULT_MAX_FRAME_SIZE + 1, false),
        (32_768, 32_768, true),
        (32_768, 32_767, true),
        (32_768, 32_769, false),
        (MIN_MAX_FRAME_SIZE, MIN_MAX_FRAME_SIZE, true),
    ];

    for (max_frame_size, payload_size, should_pass) in boundary_tests {
        let mut decoder = LiveH2DataFrameDecoder::new();
        assert!(matches!(
            decoder.process_settings(&[(SETTINGS_MAX_FRAME_SIZE_ID, max_frame_size)]),
            ParseResult::SettingsProcessed { .. }
        ));

        let result = decoder.process_data_frame(1, payload_size, false, 0, false);
        assert_boundary_result(&result, should_pass, payload_size, max_frame_size);
    }
}

fn exercise_padded_boundary_conditions() {
    let padded_tests = [
        (16_384, 16_383, 0, true),
        (16_384, 16_382, 1, true),
        (16_384, 16_384, 0, false),
        (16_384, 16_300, 80, true),
        (16_384, 16_300, 85, false),
    ];

    for (max_frame_size, payload_size, padding_size, should_pass) in padded_tests {
        let mut decoder = LiveH2DataFrameDecoder::new();
        assert!(matches!(
            decoder.process_settings(&[(SETTINGS_MAX_FRAME_SIZE_ID, max_frame_size)]),
            ParseResult::SettingsProcessed { .. }
        ));

        let result = decoder.process_data_frame(1, payload_size, true, padding_size, false);
        let total_payload_size = declared_data_payload_size(payload_size, true, padding_size)
            .expect("padded boundary values fit u32");
        assert_boundary_result(&result, should_pass, total_payload_size, max_frame_size);
    }
}

fn assert_boundary_result(
    result: &ParseResult,
    should_pass: bool,
    payload_size: u32,
    max_frame_size: u32,
) {
    if should_pass {
        assert!(
            matches!(result, ParseResult::DataFrameProcessed { .. }),
            "frame with payload {payload_size} should be accepted at limit {max_frame_size}, got {result:?}"
        );
    } else {
        assert!(
            matches!(result, ParseResult::FrameSizeError),
            "frame with payload {payload_size} should be rejected at limit {max_frame_size}, got {result:?}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_frame_at_default_max() {
        let mut decoder = LiveH2DataFrameDecoder::new();
        let result = decoder.process_data_frame(1, DEFAULT_MAX_FRAME_SIZE, false, 0, false);

        match result {
            ParseResult::DataFrameProcessed { payload_size, .. } => {
                assert_eq!(payload_size, DEFAULT_MAX_FRAME_SIZE);
            }
            other => panic!("Expected data frame processed, got: {:?}", other),
        }
    }

    #[test]
    fn test_data_frame_above_max() {
        let mut decoder = LiveH2DataFrameDecoder::new();
        let result = decoder.process_data_frame(1, DEFAULT_MAX_FRAME_SIZE + 1, false, 0, false);
        assert!(matches!(result, ParseResult::FrameSizeError));
    }

    #[test]
    fn test_custom_max_frame_size() {
        let mut decoder = LiveH2DataFrameDecoder::new();
        let custom_size = 32_768;
        assert!(matches!(
            decoder.process_settings(&[(SETTINGS_MAX_FRAME_SIZE_ID, custom_size)]),
            ParseResult::SettingsProcessed { .. }
        ));

        let result = decoder.process_data_frame(1, custom_size, false, 0, false);
        assert!(matches!(result, ParseResult::DataFrameProcessed { .. }));

        let result = decoder.process_data_frame(1, custom_size + 1, false, 0, false);
        assert!(matches!(result, ParseResult::FrameSizeError));
    }

    #[test]
    fn test_padded_data_frame_boundary() {
        let mut decoder = LiveH2DataFrameDecoder::new();
        let result = decoder.process_data_frame(1, 16_382, true, 1, false);

        match result {
            ParseResult::DataFrameProcessed { payload_size, .. } => {
                assert_eq!(payload_size, 16_384);
            }
            other => panic!("Expected padded frame accepted, got: {:?}", other),
        }

        let result = decoder.process_data_frame(1, 16_383, true, 1, false);
        assert!(matches!(result, ParseResult::FrameSizeError));
    }

    #[test]
    fn test_invalid_max_frame_size_settings() {
        let mut decoder = LiveH2DataFrameDecoder::new();

        let result =
            decoder.process_settings(&[(SETTINGS_MAX_FRAME_SIZE_ID, MIN_MAX_FRAME_SIZE - 1)]);
        assert!(matches!(
            result,
            ParseResult::ProtocolError(ErrorCode::ProtocolError)
        ));

        let result = decoder.process_settings(&[(SETTINGS_MAX_FRAME_SIZE_ID, MAX_FRAME_SIZE + 1)]);
        assert!(matches!(
            result,
            ParseResult::ProtocolError(ErrorCode::ProtocolError)
        ));

        assert!(matches!(
            decoder.process_settings(&[(SETTINGS_MAX_FRAME_SIZE_ID, MIN_MAX_FRAME_SIZE)]),
            ParseResult::SettingsProcessed { .. }
        ));

        assert!(matches!(
            decoder.process_settings(&[(SETTINGS_MAX_FRAME_SIZE_ID, MAX_FRAME_SIZE)]),
            ParseResult::SettingsProcessed { .. }
        ));
    }

    #[test]
    fn test_zero_payload_data_frame() {
        let mut decoder = LiveH2DataFrameDecoder::new();
        let result = decoder.process_data_frame(1, 0, false, 0, false);
        match result {
            ParseResult::DataFrameProcessed { payload_size, .. } => {
                assert_eq!(payload_size, 0);
            }
            other => panic!("Expected zero-length frame accepted, got: {:?}", other),
        }
    }

    #[test]
    fn test_data_frame_encoding() {
        let frame = encode_data_frame(1, 1_000, false, 0, true, true);

        assert_eq!(frame[3], FrameType::Data as u8);
        assert_eq!(frame[4], data_flags::END_STREAM);
        assert_eq!(
            u32::from_be_bytes([frame[5], frame[6], frame[7], frame[8]]),
            1
        );
        assert_eq!(frame.len() - 9, 1_000);
        assert!(frame[9..].iter().all(|byte| *byte == 0x42));
    }

    #[test]
    fn test_padded_data_frame_encoding() {
        let padding_size = 10;
        let frame = encode_data_frame(1, 100, true, padding_size, false, true);

        let expected_total = 1 + 100 + usize::from(padding_size);
        assert_eq!(frame.len() - 9, expected_total);

        assert_eq!(frame[9], padding_size);
        assert!(frame[10..110].iter().all(|byte| *byte == 0x42));
        assert!(frame[110..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn test_maximum_possible_frame_size() {
        let mut decoder = LiveH2DataFrameDecoder::new();
        assert!(matches!(
            decoder.process_settings(&[(SETTINGS_MAX_FRAME_SIZE_ID, MAX_FRAME_SIZE)]),
            ParseResult::SettingsProcessed { .. }
        ));

        let result = decoder.process_data_frame(1, MAX_FRAME_SIZE, false, 0, false);
        assert!(matches!(
            result,
            ParseResult::SkippedLargeAcceptedCandidate {
                payload_size: MAX_FRAME_SIZE,
                max_frame_size: MAX_FRAME_SIZE
            }
        ));

        let result = decoder.process_data_frame(1, MAX_FRAME_SIZE + 1, false, 0, false);
        assert!(matches!(result, ParseResult::InvalidWireLength { .. }));
    }
}
