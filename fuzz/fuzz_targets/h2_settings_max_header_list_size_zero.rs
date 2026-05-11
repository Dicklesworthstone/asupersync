#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::http::h2::frame::{HeadersFrame, SettingsFrame};
use asupersync::http::h2::settings::{DEFAULT_MAX_HEADER_LIST_SIZE, MAX_INITIAL_WINDOW_SIZE};
use asupersync::http::h2::{Connection, ErrorCode, Frame, Header, HpackEncoder, Setting, Settings};
use libfuzzer_sys::fuzz_target;

const MAX_FOLLOWUP_SETTINGS: usize = 8;
const MAX_SCENARIOS: usize = 4;
const MAX_EXTRA_HEADERS: usize = 8;
const MAX_COMPONENT_LEN: usize = 96;
const MAX_DRAIN_FRAMES: usize = 16;

#[derive(Arbitrary, Debug)]
struct SettingsZeroHeaderInput {
    initial_max_header_size: HeaderListSize,
    followup_header_sizes: Vec<HeaderListSize>,
    request_scenarios: Vec<RequestScenario>,
    connection_config: ConnectionConfig,
    drain_budget: u8,
}

#[derive(Arbitrary, Debug, Clone)]
struct RequestScenario {
    pseudo_headers: PseudoHeaders,
    regular_headers: Vec<HeaderPair>,
    end_stream: bool,
}

#[derive(Arbitrary, Debug, Clone)]
struct PseudoHeaders {
    method: String,
    path: String,
    scheme: String,
    authority: Option<String>,
}

#[derive(Arbitrary, Debug, Clone)]
struct HeaderPair {
    name: String,
    value: String,
}

#[derive(Arbitrary, Debug, Clone)]
struct ConnectionConfig {
    is_client: bool,
    initial_window_size: u32,
    enable_push: bool,
    max_concurrent_streams: u32,
}

#[derive(Arbitrary, Debug, Clone)]
enum HeaderListSize {
    Zero,
    One,
    Default,
    Tiny(u8),
    Small(u16),
    Large(u32),
    Unlimited,
}

impl HeaderListSize {
    fn to_u32(&self) -> u32 {
        match self {
            Self::Zero => 0,
            Self::One => 1,
            Self::Default => DEFAULT_MAX_HEADER_LIST_SIZE,
            Self::Tiny(value) => u32::from(*value),
            Self::Small(value) => u32::from(*value),
            Self::Large(value) => *value,
            Self::Unlimited => u32::MAX,
        }
    }
}

fuzz_target!(|input: SettingsZeroHeaderInput| {
    if input.request_scenarios.len() > MAX_SCENARIOS * 4
        || input.followup_header_sizes.len() > MAX_FOLLOWUP_SETTINGS * 4
    {
        return;
    }

    exercise_remote_zero_setting(&input);

    for scenario in input.request_scenarios.iter().take(MAX_SCENARIOS) {
        exercise_local_zero_decoder(scenario);
    }
});

fn exercise_remote_zero_setting(input: &SettingsZeroHeaderInput) {
    let local_settings = settings_from_config(
        &input.connection_config,
        input.initial_max_header_size.to_u32(),
    );
    let mut connection = if input.connection_config.is_client {
        Connection::client(local_settings)
    } else {
        Connection::server(local_settings)
    };

    process_header_list_setting(&mut connection, 0);

    let mut last_size = 0;
    for size in input
        .followup_header_sizes
        .iter()
        .take(MAX_FOLLOWUP_SETTINGS)
    {
        last_size = size.to_u32();
        process_header_list_setting(&mut connection, last_size);
    }

    assert_eq!(
        connection.remote_settings().max_header_list_size,
        last_size,
        "production connection must retain the last accepted peer header-list-size setting",
    );

    for scenario in input.request_scenarios.iter().take(MAX_SCENARIOS) {
        let headers = request_headers_from_scenario(scenario);
        match connection.open_stream(headers, scenario.end_stream) {
            Ok(stream_id) => {
                assert!(
                    connection.stream(stream_id).is_some(),
                    "opened stream should be visible in production stream store",
                );
                drain_pending_frames(&mut connection, input.drain_budget);
            }
            Err(err) => {
                assert_ne!(
                    err.code,
                    ErrorCode::NoError,
                    "failed open_stream must carry an actual HTTP/2 error",
                );
            }
        }
    }
}

fn process_header_list_setting(connection: &mut Connection, size: u32) {
    let result = connection.process_frame(Frame::Settings(SettingsFrame::new(vec![
        Setting::MaxHeaderListSize(size),
    ])));
    assert!(
        result.is_ok(),
        "SETTINGS_MAX_HEADER_LIST_SIZE has no protocol lower bound, including zero",
    );
    assert_eq!(
        connection.remote_settings().max_header_list_size,
        size,
        "production remote settings must reflect accepted SETTINGS_MAX_HEADER_LIST_SIZE",
    );

    match connection.next_frame() {
        Some(Frame::Settings(frame)) => {
            assert!(frame.ack, "accepted SETTINGS must queue a SETTINGS ACK");
            assert!(
                frame.settings.is_empty(),
                "SETTINGS ACK must not carry a payload",
            );
        }
        other => panic!("accepted SETTINGS should queue ACK before other frames: {other:?}"),
    }
}

fn exercise_local_zero_decoder(scenario: &RequestScenario) {
    let mut settings = Settings::server();
    settings.max_header_list_size = 0;
    let mut connection = Connection::server(settings);
    let headers = request_headers_from_scenario(scenario);

    let mut encoded = BytesMut::new();
    HpackEncoder::new().encode(&headers, &mut encoded);

    let result = connection.process_frame(Frame::Headers(HeadersFrame::new(
        1,
        encoded.freeze(),
        scenario.end_stream,
        true,
    )));

    assert!(
        result.is_err(),
        "a local SETTINGS_MAX_HEADER_LIST_SIZE=0 decoder should reject non-empty request headers",
    );
    let err = result.unwrap_err();
    assert!(
        matches!(
            err.code,
            ErrorCode::CompressionError | ErrorCode::ProtocolError | ErrorCode::EnhanceYourCalm
        ),
        "local zero header-list-size rejection should be a protocol/compression style error: {err}",
    );
}

fn settings_from_config(config: &ConnectionConfig, max_header_list_size: u32) -> Settings {
    let mut settings = if config.is_client {
        Settings::client()
    } else {
        Settings::server()
    };
    settings.initial_window_size = config.initial_window_size.min(MAX_INITIAL_WINDOW_SIZE);
    settings.enable_push = config.enable_push;
    settings.max_concurrent_streams = config.max_concurrent_streams.max(1);
    settings.max_header_list_size = max_header_list_size;
    settings
}

fn drain_pending_frames(connection: &mut Connection, drain_budget: u8) {
    let budget = usize::from(drain_budget).min(MAX_DRAIN_FRAMES);
    for _ in 0..budget {
        let Some(frame) = connection.next_frame() else {
            return;
        };
        match frame {
            Frame::Settings(settings) => {
                assert!(
                    settings.ack || !settings.settings.is_empty(),
                    "non-ACK SETTINGS should carry at least one setting",
                );
            }
            Frame::Headers(headers) => {
                assert_ne!(headers.stream_id, 0, "HEADERS must be stream-scoped");
            }
            Frame::Continuation(continuation) => {
                assert_ne!(
                    continuation.stream_id, 0,
                    "CONTINUATION must be stream-scoped",
                );
            }
            _ => {}
        }
    }
}

fn request_headers_from_scenario(scenario: &RequestScenario) -> Vec<Header> {
    let mut headers = Vec::with_capacity(4 + scenario.regular_headers.len().min(MAX_EXTRA_HEADERS));
    headers.push(Header::new(
        ":method",
        bounded_visible_ascii(&scenario.pseudo_headers.method, "GET", MAX_COMPONENT_LEN)
            .to_ascii_uppercase(),
    ));
    headers.push(Header::new(
        ":path",
        normalized_path(&scenario.pseudo_headers.path),
    ));
    headers.push(Header::new(
        ":scheme",
        normalized_scheme(&scenario.pseudo_headers.scheme),
    ));
    headers.push(Header::new(
        ":authority",
        scenario.pseudo_headers.authority.as_deref().map_or_else(
            || "example.test".to_string(),
            |authority| bounded_visible_ascii(authority, "example.test", MAX_COMPONENT_LEN),
        ),
    ));

    for (index, header) in scenario
        .regular_headers
        .iter()
        .take(MAX_EXTRA_HEADERS)
        .enumerate()
    {
        headers.push(Header::new(
            normalized_header_name(&header.name, index),
            bounded_visible_ascii(&header.value, "value", MAX_COMPONENT_LEN),
        ));
    }

    headers
}

fn normalized_path(path: &str) -> String {
    let mut path = bounded_visible_ascii(path, "/", MAX_COMPONENT_LEN);
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    path
}

fn normalized_scheme(scheme: &str) -> &'static str {
    if scheme.eq_ignore_ascii_case("http") {
        "http"
    } else {
        "https"
    }
}

fn normalized_header_name(name: &str, index: usize) -> String {
    let mut normalized = String::new();
    for byte in name.bytes().take(MAX_COMPONENT_LEN) {
        let lower = byte.to_ascii_lowercase();
        if lower.is_ascii_lowercase() || lower.is_ascii_digit() || lower == b'-' {
            normalized.push(char::from(lower));
        }
    }

    if normalized.is_empty() || normalized.starts_with(':') {
        format!("x-fuzz-{index}")
    } else {
        normalized
    }
}

fn bounded_visible_ascii(input: &str, fallback: &str, max_len: usize) -> String {
    let mut out = String::new();
    for byte in input.bytes().take(max_len) {
        match byte {
            b'\r' | b'\n' | b'\0' => out.push('-'),
            0x20..=0x7e => out.push(char::from(byte)),
            _ => {}
        }
    }

    if out.is_empty() {
        fallback.to_string()
    } else {
        out
    }
}
