#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::frame::{
    FrameHeader, FrameType, MAX_FRAME_SIZE, MIN_MAX_FRAME_SIZE, Setting,
    SettingsFrame as H2SettingsFrame, settings_flags,
};
use asupersync::http::h2::{ErrorCode, H2Error};
use libfuzzer_sys::fuzz_target;

const MAX_FRAMES_PER_INPUT: usize = 32;
const MAX_SETTINGS_PER_SIDE: usize = 32;
const MAX_TRAILING_BYTES: usize = 5;
const MAX_BOUNDARY_PROBES: usize = 32;
const MAX_FRAME_SIZE_SETTING_ID: u16 = 0x5;
const KNOWN_SETTING_IDS: [u16; 6] = [0x1, 0x2, 0x3, 0x4, 0x5, 0x6];

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    frames: Vec<FuzzSettingsFrame>,
    boundary_values: Vec<FrameSizeValue>,
}

#[derive(Arbitrary, Debug, Clone)]
struct FuzzSettingsFrame {
    flags: u8,
    stream_id: u32,
    prefix_settings: Vec<SettingParameter>,
    max_frame_size_value: FrameSizeValue,
    suffix_settings: Vec<SettingParameter>,
    trailing_payload_bytes: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
struct SettingParameter {
    id: u16,
    value: u32,
}

#[derive(Arbitrary, Debug, Clone)]
enum FrameSizeValue {
    Minimum,
    MinimumMinus(u16),
    MinimumPlus(u32),
    Maximum,
    MaximumMinus(u32),
    MaximumPlus(u32),
    Zero,
    One,
    HalfMinimum,
    Arbitrary(u32),
    SaturatingProduct(u32, u32),
    SaturatingDifference(u32, u32),
    PowerOfTwo(u8),
    BitMask(u32),
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let input: FuzzInput = match u.arbitrary() {
        Ok(input) => input,
        Err(_) => return,
    };

    if input.frames.len() > MAX_FRAMES_PER_INPUT {
        return;
    }

    for frame in &input.frames {
        if frame.prefix_settings.len() > MAX_SETTINGS_PER_SIDE
            || frame.suffix_settings.len() > MAX_SETTINGS_PER_SIDE
        {
            continue;
        }
        exercise_frame(frame);
    }

    for value in input.boundary_values.iter().take(MAX_BOUNDARY_PROBES) {
        exercise_single_max_frame_size(value.to_u32());
    }
});

impl FrameSizeValue {
    fn to_u32(&self) -> u32 {
        match self {
            Self::Minimum => MIN_MAX_FRAME_SIZE,
            Self::MinimumMinus(offset) => {
                MIN_MAX_FRAME_SIZE.saturating_sub(u32::from(*offset).saturating_add(1))
            }
            Self::MinimumPlus(offset) => MIN_MAX_FRAME_SIZE.saturating_add(*offset),
            Self::Maximum => MAX_FRAME_SIZE,
            Self::MaximumMinus(offset) => MAX_FRAME_SIZE.saturating_sub(*offset),
            Self::MaximumPlus(offset) => MAX_FRAME_SIZE.saturating_add(offset.saturating_add(1)),
            Self::Zero => 0,
            Self::One => 1,
            Self::HalfMinimum => MIN_MAX_FRAME_SIZE / 2,
            Self::Arbitrary(value) | Self::BitMask(value) => *value,
            Self::SaturatingProduct(lhs, rhs) => lhs.saturating_mul(*rhs),
            Self::SaturatingDifference(lhs, rhs) => lhs.saturating_sub(*rhs),
            Self::PowerOfTwo(exp) => {
                if *exp < 32 {
                    1u32 << u32::from(*exp)
                } else {
                    u32::MAX
                }
            }
        }
    }
}

fn exercise_frame(frame: &FuzzSettingsFrame) {
    let wire = build_settings_frame_wire(frame);
    let mut src = BytesMut::from(wire);
    let header = FrameHeader::parse(&mut src).expect("generated SETTINGS header is complete");
    let payload = src.freeze();
    assert_eq!(header.frame_type, FrameType::Settings as u8);
    assert_eq!(header.length as usize, payload.len());

    let result = H2SettingsFrame::parse(&header, &payload);
    if let Some(expected) = expected_error(&header, &payload) {
        assert_error_shape(result, expected);
        return;
    }

    let parsed = result.expect("valid SETTINGS frame should parse");
    assert_eq!(parsed.ack, header.has_flag(settings_flags::ACK));
    if parsed.ack {
        assert!(parsed.settings.is_empty());
    } else {
        assert_known_settings_match_payload(&payload, &parsed);
        assert_parsed_max_frame_sizes_are_in_range(&parsed);
    }

    let reparsed = encode_then_parse(&parsed);
    assert_eq!(reparsed.ack, parsed.ack);
    assert_eq!(reparsed.settings, parsed.settings);
}

fn exercise_single_max_frame_size(value: u32) {
    let frame = FuzzSettingsFrame {
        flags: 0,
        stream_id: 0,
        prefix_settings: Vec::new(),
        max_frame_size_value: FrameSizeValue::Arbitrary(value),
        suffix_settings: Vec::new(),
        trailing_payload_bytes: Vec::new(),
    };
    let wire = build_settings_frame_wire(&frame);
    let mut src = BytesMut::from(wire);
    let header = FrameHeader::parse(&mut src).expect("generated SETTINGS header is complete");
    let payload = src.freeze();
    let result = H2SettingsFrame::parse(&header, &payload);

    if !(MIN_MAX_FRAME_SIZE..=MAX_FRAME_SIZE).contains(&value) {
        assert_error_shape(
            result,
            ExpectedSettingsError {
                code: ErrorCode::ProtocolError,
                message: "SETTINGS_MAX_FRAME_SIZE out of bounds",
            },
        );
        return;
    }

    let parsed = result.expect("valid SETTINGS_MAX_FRAME_SIZE should parse");
    assert_eq!(parsed.settings, vec![Setting::MaxFrameSize(value)]);
    assert_parsed_max_frame_sizes_are_in_range(&parsed);
}

fn build_settings_frame_wire(frame: &FuzzSettingsFrame) -> Vec<u8> {
    let payload = build_settings_payload(frame);
    let header = FrameHeader {
        length: payload.len() as u32,
        frame_type: FrameType::Settings as u8,
        flags: frame.flags,
        stream_id: frame.stream_id & 0x7fff_ffff,
    };

    let mut wire = BytesMut::new();
    header.write(&mut wire);
    wire.extend_from_slice(&payload);
    wire.to_vec()
}

fn build_settings_payload(frame: &FuzzSettingsFrame) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        (frame.prefix_settings.len() + 1 + frame.suffix_settings.len()) * 6 + MAX_TRAILING_BYTES,
    );
    for setting in &frame.prefix_settings {
        append_setting(&mut payload, setting.id, setting.value);
    }
    append_setting(
        &mut payload,
        MAX_FRAME_SIZE_SETTING_ID,
        frame.max_frame_size_value.to_u32(),
    );
    for setting in &frame.suffix_settings {
        append_setting(&mut payload, setting.id, setting.value);
    }
    payload.extend(
        frame
            .trailing_payload_bytes
            .iter()
            .take(MAX_TRAILING_BYTES)
            .copied(),
    );
    payload
}

fn append_setting(payload: &mut Vec<u8>, id: u16, value: u32) {
    payload.extend_from_slice(&id.to_be_bytes());
    payload.extend_from_slice(&value.to_be_bytes());
}

#[derive(Clone, Copy, Debug)]
struct ExpectedSettingsError {
    code: ErrorCode,
    message: &'static str,
}

fn expected_error(header: &FrameHeader, payload: &Bytes) -> Option<ExpectedSettingsError> {
    if header.stream_id != 0 {
        return Some(ExpectedSettingsError {
            code: ErrorCode::ProtocolError,
            message: "SETTINGS frame with non-zero stream ID",
        });
    }

    if header.has_flag(settings_flags::ACK) && !payload.is_empty() {
        return Some(ExpectedSettingsError {
            code: ErrorCode::FrameSizeError,
            message: "SETTINGS ACK with non-zero length",
        });
    }

    if !payload.len().is_multiple_of(6) {
        return Some(ExpectedSettingsError {
            code: ErrorCode::FrameSizeError,
            message: "SETTINGS frame length not multiple of 6",
        });
    }

    first_live_setting_error(payload)
}

fn first_live_setting_error(payload: &Bytes) -> Option<ExpectedSettingsError> {
    for chunk in payload.chunks_exact(6) {
        let id = u16::from_be_bytes([chunk[0], chunk[1]]);
        let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
        match id {
            0x2 if value > 1 => {
                return Some(ExpectedSettingsError {
                    code: ErrorCode::ProtocolError,
                    message: "SETTINGS_ENABLE_PUSH must be 0 or 1",
                });
            }
            0x4 if value > 0x7fff_ffff => {
                return Some(ExpectedSettingsError {
                    code: ErrorCode::FlowControlError,
                    message: "SETTINGS_INITIAL_WINDOW_SIZE exceeds maximum",
                });
            }
            0x5 if !(MIN_MAX_FRAME_SIZE..=MAX_FRAME_SIZE).contains(&value) => {
                return Some(ExpectedSettingsError {
                    code: ErrorCode::ProtocolError,
                    message: "SETTINGS_MAX_FRAME_SIZE out of bounds",
                });
            }
            _ => {}
        }
    }
    None
}

fn assert_known_settings_match_payload(payload: &Bytes, parsed: &H2SettingsFrame) {
    let expected = expected_known_settings(payload);
    assert_eq!(parsed.settings, expected);
    assert_eq!(
        parsed.settings.len(),
        payload.chunks_exact(6).count() - unknown_setting_count(payload)
    );
    assert!(
        parsed
            .settings
            .iter()
            .all(|setting| KNOWN_SETTING_IDS.contains(&setting.id()))
    );
}

fn expected_known_settings(payload: &Bytes) -> Vec<Setting> {
    payload
        .chunks_exact(6)
        .filter_map(|chunk| {
            let id = u16::from_be_bytes([chunk[0], chunk[1]]);
            let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
            Setting::from_id_value(id, value)
        })
        .collect()
}

fn unknown_setting_count(payload: &Bytes) -> usize {
    payload
        .chunks_exact(6)
        .filter(|chunk| {
            let id = u16::from_be_bytes([chunk[0], chunk[1]]);
            !KNOWN_SETTING_IDS.contains(&id)
        })
        .count()
}

fn assert_parsed_max_frame_sizes_are_in_range(parsed: &H2SettingsFrame) {
    for setting in &parsed.settings {
        if let Setting::MaxFrameSize(value) = *setting {
            assert!(
                (MIN_MAX_FRAME_SIZE..=MAX_FRAME_SIZE).contains(&value),
                "parsed SETTINGS_MAX_FRAME_SIZE must stay within RFC range"
            );
        }
    }
}

fn assert_error_shape(result: Result<H2SettingsFrame, H2Error>, expected: ExpectedSettingsError) {
    match result {
        Ok(frame) => panic!("expected {expected:?}, parsed SETTINGS frame: {frame:?}"),
        Err(err) => {
            assert_eq!(
                err.code, expected.code,
                "unexpected SETTINGS parse error code: {err}"
            );
            assert!(
                err.is_connection_error(),
                "SETTINGS parse errors should be connection-scoped: {err:?}"
            );
            assert_eq!(
                err.stream_id, None,
                "SETTINGS parse errors should not attach a stream id"
            );
            assert_eq!(
                err.message, expected.message,
                "SETTINGS parse error should keep the exact live diagnostic"
            );
            assert_eq!(
                err.to_string(),
                format!(
                    "HTTP/2 connection error ({}): {}",
                    expected.code, expected.message
                ),
                "SETTINGS parse error should keep stable Display output"
            );
        }
    }
}

fn encode_then_parse(frame: &H2SettingsFrame) -> H2SettingsFrame {
    let mut encoded = BytesMut::new();
    frame
        .encode(&mut encoded)
        .expect("accepted SETTINGS encodes");
    let header = FrameHeader::parse(&mut encoded).expect("encoded SETTINGS header parses");
    assert_eq!(header.frame_type, FrameType::Settings as u8);
    let payload = encoded.freeze();
    assert_eq!(header.length as usize, payload.len());
    H2SettingsFrame::parse(&header, &payload).expect("encoded SETTINGS parses")
}
