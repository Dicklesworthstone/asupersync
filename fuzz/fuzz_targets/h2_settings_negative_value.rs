#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::BytesMut;
use asupersync::http::h2::frame::{
    FRAME_HEADER_SIZE, Frame, FrameHeader, FrameType, Setting, parse_frame,
};

#[derive(Arbitrary, Debug)]
struct H2SettingsNegativeValueInput {
    setting_selector: u8,
    low_bits: u32,
}

fuzz_target!(|input: H2SettingsNegativeValueInput| {
    let setting_id = setting_id(input.setting_selector);
    let value = 0x8000_0000 | (input.low_bits & 0x7fff_ffff);
    let frame = settings_frame(setting_id, value);

    let mut bytes = BytesMut::new();
    bytes.extend_from_slice(&frame);

    let header = FrameHeader::parse(&mut bytes).expect("complete SETTINGS frame header");
    assert_eq!(header.length, 6);
    assert_eq!(header.frame_type, FrameType::Settings as u8);
    assert_eq!(header.stream_id, 0);

    let payload = bytes.split_to(header.length as usize).freeze();
    let parsed = parse_frame(&header, payload);

    match setting_id {
        0x1 => expect_unsigned_setting(
            parsed,
            |setting| matches!(setting, Setting::HeaderTableSize(parsed) if parsed == value),
        ),
        0x3 => expect_unsigned_setting(
            parsed,
            |setting| matches!(setting, Setting::MaxConcurrentStreams(parsed) if parsed == value),
        ),
        0x6 => expect_unsigned_setting(
            parsed,
            |setting| matches!(setting, Setting::MaxHeaderListSize(parsed) if parsed == value),
        ),
        0x2 | 0x4 | 0x5 => {
            assert!(
                parsed.is_err(),
                "RFC-constrained SETTINGS value with sign bit set must be rejected"
            );
        }
        _ => {
            let Frame::Settings(settings) = parsed.expect("unknown SETTINGS id should be ignored")
            else {
                panic!("SETTINGS frame parsed as non-SETTINGS frame");
            };
            assert!(
                settings.settings.is_empty(),
                "unknown SETTINGS id must be ignored regardless of value bits"
            );
        }
    }
});

fn setting_id(selector: u8) -> u16 {
    match selector % 7 {
        0 => 0x1,    // SETTINGS_HEADER_TABLE_SIZE: full u32
        1 => 0x2,    // SETTINGS_ENABLE_PUSH: RFC-limited to 0 or 1
        2 => 0x3,    // SETTINGS_MAX_CONCURRENT_STREAMS: full u32
        3 => 0x4,    // SETTINGS_INITIAL_WINDOW_SIZE: RFC-limited to 2^31 - 1
        4 => 0x5,    // SETTINGS_MAX_FRAME_SIZE: RFC-limited to 2^14..2^24 - 1
        5 => 0x6,    // SETTINGS_MAX_HEADER_LIST_SIZE: full u32
        _ => 0xffff, // unknown settings are ignored
    }
}

fn settings_frame(setting_id: u16, value: u32) -> [u8; FRAME_HEADER_SIZE + 6] {
    let mut frame = [0u8; FRAME_HEADER_SIZE + 6];
    frame[2] = 6;
    frame[3] = FrameType::Settings as u8;
    frame[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + 2].copy_from_slice(&setting_id.to_be_bytes());
    frame[FRAME_HEADER_SIZE + 2..].copy_from_slice(&value.to_be_bytes());
    frame
}

fn expect_unsigned_setting<F>(
    parsed: Result<Frame, asupersync::http::h2::error::H2Error>,
    matches: F,
) where
    F: FnOnce(Setting) -> bool,
{
    let Frame::Settings(settings) = parsed.expect("unsigned SETTINGS value should parse") else {
        panic!("SETTINGS frame parsed as non-SETTINGS frame");
    };

    assert_eq!(settings.settings.len(), 1);
    let setting = settings.settings[0];
    assert!(
        matches(setting),
        "SETTINGS value with sign bit set was not preserved as u32: {setting:?}"
    );
}
