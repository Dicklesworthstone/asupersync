#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::frame::{
    FrameHeader, FrameType, MAX_FRAME_SIZE, MIN_MAX_FRAME_SIZE, Setting,
    SettingsFrame as H2SettingsFrame, settings_flags,
};
use asupersync::http::h2::{ErrorCode, H2Error};
use libfuzzer_sys::fuzz_target;

const MAX_SETTINGS_PER_INPUT: usize = 64;
const MAX_TRAILING_BYTES: usize = 5;
const MAX_UNKNOWN_PROBES: usize = 8;
const KNOWN_SETTING_IDS: [u16; 6] = [0x1, 0x2, 0x3, 0x4, 0x5, 0x6];

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    frame: FuzzSettingsFrame,
    unknown_probes: Vec<UnknownSettingProbe>,
}

#[derive(Arbitrary, Debug, Clone)]
struct FuzzSettingsFrame {
    flags: u8,
    stream_id: u32,
    parameters: Vec<SettingParameter>,
    trailing_payload_bytes: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone)]
struct SettingParameter {
    id: u16,
    value: u32,
}

#[derive(Arbitrary, Debug)]
struct UnknownSettingProbe {
    id: u16,
    value: u32,
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let input: FuzzInput = match u.arbitrary() {
        Ok(input) => input,
        Err(_) => return,
    };

    if input.frame.parameters.len() > MAX_SETTINGS_PER_INPUT {
        return;
    }

    exercise_frame(&input.frame);
    for probe in input.unknown_probes.iter().take(MAX_UNKNOWN_PROBES) {
        exercise_targeted_unknown(probe);
    }
});

fn exercise_frame(frame: &FuzzSettingsFrame) {
    let wire = build_settings_frame_wire(frame);
    let mut src = BytesMut::from(wire);
    let header = FrameHeader::parse(&mut src).expect("generated SETTINGS header is complete");
    let payload = src.freeze();
    assert_eq!(header.frame_type, FrameType::Settings as u8);
    assert_eq!(header.length as usize, payload.len());

    let result = H2SettingsFrame::parse(&header, &payload);

    if header.stream_id != 0 {
        assert_error_code(result, ErrorCode::ProtocolError);
        return;
    }

    let ack_flag_set = header.has_flag(settings_flags::ACK);
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
        assert_known_settings_match_payload(&payload, &parsed);
    }

    let reparsed = encode_then_parse(&parsed);
    assert_eq!(reparsed.ack, parsed.ack);
    assert_eq!(reparsed.settings, parsed.settings);
}

fn exercise_targeted_unknown(probe: &UnknownSettingProbe) {
    let unknown_id = unknown_setting_id(probe.id);
    let frame = FuzzSettingsFrame {
        flags: 0,
        stream_id: 0,
        parameters: vec![
            SettingParameter {
                id: 0x1,
                value: 4096,
            },
            SettingParameter {
                id: unknown_id,
                value: probe.value,
            },
            SettingParameter {
                id: 0x3,
                value: 123,
            },
        ],
        trailing_payload_bytes: Vec::new(),
    };

    let wire = build_settings_frame_wire(&frame);
    let mut src = BytesMut::from(wire);
    let header = FrameHeader::parse(&mut src).expect("generated SETTINGS header is complete");
    let payload = src.freeze();
    let parsed =
        H2SettingsFrame::parse(&header, &payload).expect("unknown SETTINGS ID should be ignored");

    assert_eq!(
        parsed.settings,
        vec![
            Setting::HeaderTableSize(4096),
            Setting::MaxConcurrentStreams(123)
        ]
    );
    assert!(
        !parsed
            .settings
            .iter()
            .any(|setting| setting.id() == unknown_id)
    );
    assert_known_settings_match_payload(&payload, &parsed);
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
    let mut payload = Vec::with_capacity(frame.parameters.len() * 6 + MAX_TRAILING_BYTES);
    for parameter in &frame.parameters {
        payload.extend_from_slice(&parameter.id.to_be_bytes());
        payload.extend_from_slice(&parameter.value.to_be_bytes());
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
            0x5 if !(MIN_MAX_FRAME_SIZE..=MAX_FRAME_SIZE).contains(&value) => {
                return Some(ErrorCode::ProtocolError);
            }
            _ => {}
        }
    }
    None
}

fn assert_known_settings_match_payload(payload: &Bytes, parsed: &H2SettingsFrame) {
    let expected = expected_known_settings(payload);
    assert_eq!(
        parsed.settings, expected,
        "live SETTINGS parser must preserve known settings and ignore undefined IDs"
    );
    assert_eq!(
        parsed.settings.len(),
        payload.chunks_exact(6).count() - undefined_setting_count(payload)
    );
    assert!(
        parsed
            .settings
            .iter()
            .all(|setting| KNOWN_SETTING_IDS.contains(&setting.id())),
        "parsed SETTINGS list must contain only registered IDs"
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

fn undefined_setting_count(payload: &Bytes) -> usize {
    payload
        .chunks_exact(6)
        .filter(|chunk| {
            let id = u16::from_be_bytes([chunk[0], chunk[1]]);
            !KNOWN_SETTING_IDS.contains(&id)
        })
        .count()
}

fn unknown_setting_id(id: u16) -> u16 {
    if (0x1..=0x6).contains(&id) {
        id + 0x6
    } else {
        id
    }
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
