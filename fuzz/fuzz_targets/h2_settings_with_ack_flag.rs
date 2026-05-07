#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::frame::{
    FrameHeader, FrameType, Setting, SettingsFrame as H2SettingsFrame, settings_flags,
};
use asupersync::http::h2::{ErrorCode, H2Error};
use libfuzzer_sys::fuzz_target;

/// HTTP/2 SETTINGS frame ACK flag validation testing.
/// Per RFC 9113 §6.5, SETTINGS frame with ACK flag MUST have empty payload.
/// Non-empty payload with ACK flag must be rejected as FRAME_SIZE_ERROR.
///
/// Tests:
/// - SETTINGS with ACK flag and non-empty payload (FRAME_SIZE_ERROR)
/// - SETTINGS with ACK flag and empty payload (valid)
/// - SETTINGS without ACK flag with payload (valid)
/// - Various payload sizes with ACK flag
/// - Stream ID validation (must be 0)
/// - Frame size consistency

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// SETTINGS frame to test
    settings_frame: SettingsFrame,
}

#[derive(Arbitrary, Debug, Clone)]
struct SettingsFrame {
    /// Frame flags (ACK = 0x1)
    flags: u8,
    /// Stream ID (must be 0 for SETTINGS)
    stream_id: u32,
    /// Settings payload (list of setting_id, value pairs)
    settings: Vec<SettingEntry>,
    /// Extra payload bytes for malformed length testing
    trailing_payload_bytes: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
struct SettingEntry {
    /// Setting ID (16-bit)
    id: u16,
    /// Setting value (32-bit)
    value: u32,
}

/// SETTINGS frame flags
const SETTINGS_ACK_FLAG: u8 = settings_flags::ACK;
const MAX_SETTINGS_PER_INPUT: usize = 64;
const MAX_TRAILING_BYTES: usize = 5;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let input: FuzzInput = match u.arbitrary() {
        Ok(input) => input,
        Err(_) => return, // Skip invalid inputs
    };

    // Limit generated payload size; this target is about parser semantics, not OOM.
    if input.settings_frame.settings.len() > MAX_SETTINGS_PER_INPUT {
        return;
    }

    let wire = build_settings_frame_wire(&input.settings_frame);
    let mut src = BytesMut::from(wire);
    let header = FrameHeader::parse(&mut src).expect("generated SETTINGS header is complete");
    let payload = src.freeze();
    assert_eq!(header.frame_type, FrameType::Settings as u8);
    assert_eq!(
        header.length as usize,
        payload.len(),
        "generated SETTINGS header length must match payload"
    );

    let result = H2SettingsFrame::parse(&header, &payload);

    // Live parser precedence: stream-id errors are detected before ACK/payload
    // and before individual setting validation.
    if header.stream_id != 0 {
        assert_error_code(result, ErrorCode::ProtocolError);
        return;
    }

    let ack_flag_set = header.has_flag(SETTINGS_ACK_FLAG);
    if ack_flag_set && !payload.is_empty() {
        assert_error_code(result, ErrorCode::FrameSizeError);
        return;
    }

    if !payload.len().is_multiple_of(6) {
        assert_error_code(result, ErrorCode::FrameSizeError);
        return;
    }

    if let Some(code) = first_live_setting_error(&payload) {
        assert_error_code(result, code);
        return;
    }

    let parsed = result.expect("valid SETTINGS frame should parse");
    assert_eq!(parsed.ack, ack_flag_set);
    if ack_flag_set {
        assert!(
            parsed.settings.is_empty(),
            "SETTINGS ACK must not expose payload settings"
        );
    } else {
        assert_eq!(
            parsed.settings,
            expected_known_settings(&payload),
            "live SETTINGS parser must preserve known settings and ignore unknown IDs"
        );
    }

    let reparsed = encode_then_parse(&parsed);
    assert_eq!(reparsed.ack, parsed.ack);
    assert_eq!(reparsed.settings, parsed.settings);
});

fn build_settings_frame_wire(frame: &SettingsFrame) -> Vec<u8> {
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

fn build_settings_payload(frame: &SettingsFrame) -> Vec<u8> {
    let mut payload = Vec::with_capacity(frame.settings.len() * 6 + MAX_TRAILING_BYTES);
    for setting in &frame.settings {
        payload.extend_from_slice(&setting.id.to_be_bytes());
        payload.extend_from_slice(&setting.value.to_be_bytes());
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

fn first_live_setting_error(payload: &Bytes) -> Option<ErrorCode> {
    for chunk in payload.chunks_exact(6) {
        let id = u16::from_be_bytes([chunk[0], chunk[1]]);
        let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
        match id {
            0x2 if value > 1 => return Some(ErrorCode::ProtocolError),
            0x4 if value > 0x7fff_ffff => return Some(ErrorCode::FlowControlError),
            0x5 if !(16_384..=16_777_215).contains(&value) => {
                return Some(ErrorCode::ProtocolError);
            }
            _ => {}
        }
    }
    None
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

fn assert_error_code(result: Result<H2SettingsFrame, H2Error>, expected: ErrorCode) {
    match result {
        Ok(frame) => panic!("expected {expected:?}, parsed SETTINGS frame: {frame:?}"),
        Err(err) => assert_eq!(err.code, expected, "unexpected SETTINGS parse error: {err}"),
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
