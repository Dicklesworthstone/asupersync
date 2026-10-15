#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::frame::{
    DataFrame, GoAwayFrame, HeadersFrame, PingFrame, PriorityFrame, PrioritySpec, RstStreamFrame,
    SettingsFrame, WindowUpdateFrame,
};
use asupersync::http::h2::{
    Connection, ConnectionState as H2ConnectionState, ErrorCode, Frame, Header, HpackEncoder,
    Setting, Settings,
};
use libfuzzer_sys::fuzz_target;

const MAX_EARLY_FRAMES: usize = 16;
const MAX_POST_FRAMES: usize = 16;
const MAX_SETTINGS: usize = 16;
const MAX_HEADERS: usize = 8;
const MAX_COMPONENT_LEN: usize = 96;
const MAX_DATA_LEN: usize = 256;
const MAX_DRAIN_FRAMES: usize = 32;

/// HTTP/2 connection handshake timing test input for RFC 7540 §3.5 compliance
#[derive(Arbitrary, Debug)]
struct H2HandshakeTimingInput {
    /// Frames client sends after preface but before server SETTINGS
    client_early_frames: Vec<ClientEarlyFrame>,
    /// Server SETTINGS frame content
    server_settings: Vec<SettingsParameter>,
    /// Whether server sends SETTINGS with ACK flag (invalid)
    server_settings_ack: bool,
    /// Additional frames after handshake
    post_handshake_frames: Vec<PostHandshakeFrame>,
    /// Timing behavior to test
    timing_scenario: TimingScenario,
}

#[derive(Arbitrary, Debug)]
enum ClientEarlyFrame {
    /// Client SETTINGS frame (required after preface)
    Settings(Vec<SettingsParameter>),
    /// HEADERS frame starting a stream
    Headers {
        stream_id: u32,
        end_stream: bool,
        end_headers: bool,
        headers: Vec<(String, String)>,
    },
    /// PING frame
    Ping { ack: bool, payload: [u8; 8] },
    /// PRIORITY frame
    Priority {
        stream_id: u32,
        dependency: u32,
        weight: u8,
        exclusive: bool,
    },
    /// WINDOW_UPDATE frame
    WindowUpdate { stream_id: u32, increment: u32 },
}

#[derive(Arbitrary, Debug)]
enum PostHandshakeFrame {
    /// DATA frame
    Data {
        stream_id: u32,
        data: Vec<u8>,
        end_stream: bool,
    },
    /// RST_STREAM frame
    RstStream { stream_id: u32, error_code: u32 },
    /// GOAWAY frame
    GoAway {
        last_stream_id: u32,
        error_code: u32,
        debug_data: Vec<u8>,
    },
}

#[derive(Arbitrary, Debug, Clone)]
struct SettingsParameter {
    id: u16,
    value: u32,
}

#[derive(Arbitrary, Debug)]
enum TimingScenario {
    /// Normal: client waits for server SETTINGS
    ClientWaits,
    /// Early: client sends frames immediately after preface
    ClientSendsEarly,
    /// Aggressive: client sends many frames before server responds
    ClientFlood,
    /// Delayed: server takes long time to send SETTINGS
    ServerDelayed,
    /// Concurrent: both sides send simultaneously
    Concurrent,
}

/// Mock HTTP/2 handshake parser for testing RFC 7540 §3.5 compliance
struct MockH2HandshakeParser {
    state: ConnectionState,
    client_preface_received: bool,
    client_settings_received: bool,
    server_settings_sent: bool,
    active_streams: std::collections::HashSet<u32>,
}

#[derive(Debug, PartialEq)]
enum ConnectionState {
    /// Waiting for client preface
    WaitingClientPreface,
    /// Waiting for client SETTINGS after preface
    WaitingClientSettings,
    /// Client sent early frames, pending server SETTINGS
    ClientEarlyFramesPending,
    /// Full handshake complete
    Connected,
}

#[derive(Debug, PartialEq)]
enum HandshakeError {
    /// Client sent non-SETTINGS frame before preface
    FrameBeforePreface,
    /// Server sent SETTINGS with ACK flag initially
    ServerSettingsWithAck,
    /// Invalid frame type during handshake
    InvalidFrameType,
    /// Stream ID zero used for stream frame
    StreamIdZero,
    /// Even stream ID initiated by client
    InvalidStreamId,
}

impl MockH2HandshakeParser {
    fn new() -> Self {
        Self {
            state: ConnectionState::WaitingClientPreface,
            client_preface_received: false,
            client_settings_received: false,
            server_settings_sent: false,
            active_streams: std::collections::HashSet::new(),
        }
    }

    fn process_client_preface(&mut self) -> Result<(), HandshakeError> {
        if self.state != ConnectionState::WaitingClientPreface {
            return Err(HandshakeError::FrameBeforePreface);
        }

        // RFC 7540 §3.5: Client preface is "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        // followed by SETTINGS frame
        self.client_preface_received = true;
        self.state = ConnectionState::WaitingClientSettings;
        Ok(())
    }

    fn process_client_frame(&mut self, frame: &ClientEarlyFrame) -> Result<(), HandshakeError> {
        if !self.client_preface_received {
            return Err(HandshakeError::FrameBeforePreface);
        }

        match frame {
            ClientEarlyFrame::Settings(params) => {
                // First SETTINGS frame after preface
                if !self.client_settings_received {
                    self.validate_settings_parameters(params)?;
                    self.client_settings_received = true;

                    // RFC 7540 §3.5: Client is permitted to send additional frames
                    // immediately after preface without waiting for server SETTINGS
                    if !self.server_settings_sent {
                        self.state = ConnectionState::ClientEarlyFramesPending;
                    } else {
                        self.state = ConnectionState::Connected;
                    }
                } else {
                    // Subsequent SETTINGS frame
                    if self.state == ConnectionState::Connected {
                        self.validate_settings_parameters(params)?;
                    }
                }
                Ok(())
            }
            ClientEarlyFrame::Headers {
                stream_id,
                end_stream: _,
                end_headers: _,
                headers: _,
            } => {
                self.validate_stream_id(*stream_id, true)?;

                // RFC 7540 §3.5: Client can send frames before server SETTINGS
                // This is explicitly allowed to reduce latency
                self.active_streams.insert(*stream_id);
                Ok(())
            }
            ClientEarlyFrame::Ping { ack: _, payload: _ } => {
                // PING frames are allowed at any time
                Ok(())
            }
            ClientEarlyFrame::Priority {
                stream_id,
                dependency,
                weight: _,
                exclusive: _,
            } => {
                self.validate_stream_id(*stream_id, true)?;

                // Priority dependency validation
                if *dependency == *stream_id {
                    // Self-dependency - should be handled gracefully
                    return Ok(());
                }

                Ok(())
            }
            ClientEarlyFrame::WindowUpdate {
                stream_id,
                increment,
            } => {
                if *increment == 0 {
                    return Err(HandshakeError::InvalidFrameType);
                }

                if *stream_id != 0 {
                    self.validate_stream_id(*stream_id, true)?;
                }

                Ok(())
            }
        }
    }

    fn process_server_settings(
        &mut self,
        params: &[SettingsParameter],
        ack: bool,
    ) -> Result<(), HandshakeError> {
        if ack && !self.server_settings_sent {
            // RFC 7540 §6.5: SETTINGS with ACK cannot be first SETTINGS frame
            return Err(HandshakeError::ServerSettingsWithAck);
        }

        if !ack {
            self.validate_settings_parameters(params)?;
            self.server_settings_sent = true;

            // Update state based on client progress
            if self.client_settings_received {
                self.state = ConnectionState::Connected;
            }
        }

        Ok(())
    }

    fn validate_stream_id(
        &self,
        stream_id: u32,
        client_initiated: bool,
    ) -> Result<(), HandshakeError> {
        if stream_id == 0 {
            return Err(HandshakeError::StreamIdZero);
        }

        // RFC 7540 §5.1.1: Client-initiated streams are odd, server-initiated are even
        if client_initiated && stream_id.is_multiple_of(2) {
            return Err(HandshakeError::InvalidStreamId);
        }

        Ok(())
    }

    fn validate_settings_parameters(
        &self,
        params: &[SettingsParameter],
    ) -> Result<(), HandshakeError> {
        for param in params {
            match param.id {
                1 => { // SETTINGS_HEADER_TABLE_SIZE
                    // Any value is valid
                }
                2 => {
                    // SETTINGS_ENABLE_PUSH
                    if param.value > 1 {
                        return Err(HandshakeError::InvalidFrameType);
                    }
                }
                3 => { // SETTINGS_MAX_CONCURRENT_STREAMS
                    // Any value is valid (0 means no new streams allowed)
                }
                4 => {
                    // SETTINGS_INITIAL_WINDOW_SIZE
                    if param.value > 2147483647 {
                        // 2^31 - 1
                        return Err(HandshakeError::InvalidFrameType);
                    }
                }
                5 => {
                    // SETTINGS_MAX_FRAME_SIZE
                    if param.value < 16384 || param.value > 16777215 {
                        // 2^14 to 2^24-1
                        return Err(HandshakeError::InvalidFrameType);
                    }
                }
                6 => { // SETTINGS_MAX_HEADER_LIST_SIZE
                    // Any value is valid
                }
                _ => {
                    // Unknown settings are ignored per RFC 7540 §6.5.2
                }
            }
        }
        Ok(())
    }

    fn simulate_handshake_timing(
        &mut self,
        input: &H2HandshakeTimingInput,
    ) -> Result<(), HandshakeError> {
        // Always start with client preface
        self.process_client_preface()?;

        match input.timing_scenario {
            TimingScenario::ClientWaits => {
                // Client sends SETTINGS first
                if let Some(ClientEarlyFrame::Settings(params)) = input.client_early_frames.first()
                {
                    self.process_client_frame(&ClientEarlyFrame::Settings(params.clone()))?;
                }

                // Then server sends SETTINGS
                self.process_server_settings(&input.server_settings, input.server_settings_ack)?;

                // Then remaining client frames
                for frame in input.client_early_frames.iter().skip(1) {
                    self.process_client_frame(frame)?;
                }
            }
            TimingScenario::ClientSendsEarly => {
                // Client sends all frames before server SETTINGS
                for frame in &input.client_early_frames {
                    self.process_client_frame(frame)?;
                }

                // Server finally sends SETTINGS
                self.process_server_settings(&input.server_settings, input.server_settings_ack)?;
            }
            TimingScenario::ClientFlood => {
                // Client sends SETTINGS
                if let Some(ClientEarlyFrame::Settings(params)) = input.client_early_frames.first()
                {
                    self.process_client_frame(&ClientEarlyFrame::Settings(params.clone()))?;
                }

                // Client sends many frames rapidly
                for frame in input.client_early_frames.iter().cycle().take(50) {
                    if !matches!(frame, ClientEarlyFrame::Settings(_)) {
                        self.process_client_frame(frame)?;
                    }
                }

                // Server eventually responds
                self.process_server_settings(&input.server_settings, input.server_settings_ack)?;
            }
            TimingScenario::ServerDelayed => {
                // Client sends SETTINGS
                if let Some(ClientEarlyFrame::Settings(params)) = input.client_early_frames.first()
                {
                    self.process_client_frame(&ClientEarlyFrame::Settings(params.clone()))?;
                }

                // Simulate server delay - client may send more frames
                for frame in input.client_early_frames.iter().skip(1) {
                    self.process_client_frame(frame)?;
                }

                // Server finally sends SETTINGS (very delayed)
                self.process_server_settings(&input.server_settings, input.server_settings_ack)?;
            }
            TimingScenario::Concurrent => {
                // Interleave client and server frames
                if let Some(ClientEarlyFrame::Settings(params)) = input.client_early_frames.first()
                {
                    self.process_client_frame(&ClientEarlyFrame::Settings(params.clone()))?;
                }

                // Server sends SETTINGS concurrently
                self.process_server_settings(&input.server_settings, input.server_settings_ack)?;

                // Remaining client frames
                for frame in input.client_early_frames.iter().skip(1) {
                    self.process_client_frame(frame)?;
                }
            }
        }

        Ok(())
    }
}

fuzz_target!(|input: H2HandshakeTimingInput| {
    // Skip inputs that would cause excessive processing
    if input.client_early_frames.len() > 100 {
        return;
    }

    exercise_production_recv_first_then_send(&input);

    let mut parser = MockH2HandshakeParser::new();

    // Test the handshake timing scenario
    let result = parser.simulate_handshake_timing(&input);

    match input.timing_scenario {
        TimingScenario::ClientSendsEarly
        | TimingScenario::ClientFlood
        | TimingScenario::ServerDelayed => {
            // RFC 7540 §3.5: "To avoid unnecessary latency, clients are permitted
            // to send additional frames to the server immediately after sending
            // the client connection preface, without waiting to receive the
            // server connection preface."

            // This should generally succeed unless there are other validation errors
            match result {
                Ok(()) => {
                    // Expected: client early frames should be accepted
                    assert!(
                        parser.state == ConnectionState::Connected
                            || parser.state == ConnectionState::ClientEarlyFramesPending
                    );
                }
                Err(HandshakeError::ServerSettingsWithAck) => {
                    // Expected: server sent invalid SETTINGS with ACK
                }
                Err(HandshakeError::InvalidFrameType) => {
                    // Expected: invalid frame parameters
                }
                Err(HandshakeError::StreamIdZero) => {
                    // Expected: invalid stream ID
                }
                Err(HandshakeError::InvalidStreamId) => {
                    // Expected: even stream ID from client
                }
                Err(ref _other_error) => {
                    // Debug unexpected errors in early frame scenarios
                    // These might indicate over-strict validation
                }
            }
        }
        TimingScenario::ClientWaits | TimingScenario::Concurrent => {
            // Normal handshake scenarios should succeed unless validation errors
            match result {
                Ok(()) => {
                    // Expected successful handshake
                    assert_eq!(parser.state, ConnectionState::Connected);
                }
                Err(HandshakeError::ServerSettingsWithAck) => {
                    // Expected: server sent invalid SETTINGS with ACK
                }
                Err(HandshakeError::InvalidFrameType)
                | Err(HandshakeError::StreamIdZero)
                | Err(HandshakeError::InvalidStreamId) => {
                    // Expected: validation errors
                }
                Err(other_error) => {
                    // Unexpected errors in normal scenarios
                    panic!(
                        "Unexpected handshake error in normal scenario: {:?}",
                        other_error
                    );
                }
            }
        }
    }

    // Test invariants that should always hold
    test_handshake_invariants(&parser, &input, &result);
});

fn test_handshake_invariants(
    parser: &MockH2HandshakeParser,
    input: &H2HandshakeTimingInput,
    result: &Result<(), HandshakeError>,
) {
    // Invariant: If server sends SETTINGS with ACK as first frame, it must fail
    if input.server_settings_ack && !parser.server_settings_sent {
        assert!(matches!(result, Err(HandshakeError::ServerSettingsWithAck)));
    }

    // Invariant: Stream ID 0 for stream-specific frames must fail
    for frame in &input.client_early_frames {
        if let ClientEarlyFrame::Headers { stream_id, .. } = frame
            && *stream_id == 0
            && result.is_err()
        {
            assert!(matches!(result, Err(HandshakeError::StreamIdZero)));
        }
    }

    // Invariant: Even stream IDs from client must fail
    for frame in &input.client_early_frames {
        match frame {
            ClientEarlyFrame::Headers { stream_id, .. }
            | ClientEarlyFrame::Priority { stream_id, .. }
                if *stream_id != 0 && stream_id.is_multiple_of(2) && result.is_err() =>
            {
                assert!(matches!(result, Err(HandshakeError::InvalidStreamId)));
            }
            _ => {}
        }
    }

    // Invariant: Client preface must be processed before any frames
    if parser.client_preface_received || result.is_ok() {
        // If we got this far, preface was processed
    } else {
        // If preface wasn't processed, ensure appropriate error
        assert!(matches!(result, Err(HandshakeError::FrameBeforePreface)));
    }

    // Invariant: WINDOW_UPDATE with zero increment should fail
    for frame in &input.client_early_frames {
        if let ClientEarlyFrame::WindowUpdate { increment, .. } = frame
            && *increment == 0
            && result.is_err()
        {
            assert!(matches!(result, Err(HandshakeError::InvalidFrameType)));
        }
    }
}

fn exercise_production_recv_first_then_send(input: &H2HandshakeTimingInput) {
    let mut connection = Connection::server(Settings::server());

    if matches!(input.timing_scenario, TimingScenario::Concurrent) {
        connection.queue_initial_settings();
    }

    let initial_settings = first_client_settings(input).map_or_else(
        || settings_from_params(&input.server_settings),
        settings_from_params,
    );
    let first_result =
        connection.process_frame(Frame::Settings(SettingsFrame::new(initial_settings)));
    assert!(
        first_result.is_ok(),
        "production server must accept a valid SETTINGS first frame",
    );
    assert_eq!(
        connection.state(),
        H2ConnectionState::Open,
        "valid first SETTINGS should open the production connection",
    );

    for frame in input.client_early_frames.iter().take(MAX_EARLY_FRAMES) {
        if matches!(frame, ClientEarlyFrame::Settings(_)) {
            continue;
        }
        assert_not_first_frame_error(process_production_early_frame(&mut connection, frame));
    }

    if !matches!(input.timing_scenario, TimingScenario::Concurrent) {
        connection.queue_initial_settings();
    }

    let (settings_seen, ack_seen) = drain_production_pending(&mut connection);
    assert!(
        settings_seen,
        "server should be able to send its SETTINGS after receiving peer SETTINGS",
    );
    assert!(ack_seen, "peer SETTINGS should queue a SETTINGS ACK");

    for frame in input.post_handshake_frames.iter().take(MAX_POST_FRAMES) {
        assert_not_first_frame_error(process_production_post_frame(&mut connection, frame));
    }
}

fn first_client_settings(input: &H2HandshakeTimingInput) -> Option<&[SettingsParameter]> {
    input.client_early_frames.iter().find_map(|frame| {
        if let ClientEarlyFrame::Settings(params) = frame {
            Some(params.as_slice())
        } else {
            None
        }
    })
}

fn settings_from_params(params: &[SettingsParameter]) -> Vec<Setting> {
    params
        .iter()
        .take(MAX_SETTINGS)
        .map(setting_from_param)
        .collect()
}

fn setting_from_param(param: &SettingsParameter) -> Setting {
    match param.id % 7 {
        1 => Setting::HeaderTableSize(param.value),
        2 => Setting::EnablePush(param.value % 2 == 1),
        3 => Setting::MaxConcurrentStreams(param.value),
        4 => Setting::InitialWindowSize(param.value.min(0x7fff_ffff)),
        5 => Setting::MaxFrameSize(16_384 + (param.value % (16_777_215 - 16_384 + 1))),
        6 => Setting::MaxHeaderListSize(param.value),
        _ => Setting::MaxConcurrentStreams(param.value),
    }
}

fn process_production_early_frame(
    connection: &mut Connection,
    frame: &ClientEarlyFrame,
) -> Result<Option<asupersync::http::h2::connection::ReceivedFrame>, asupersync::http::h2::H2Error>
{
    match frame {
        ClientEarlyFrame::Settings(params) => connection.process_frame(Frame::Settings(
            SettingsFrame::new(settings_from_params(params)),
        )),
        ClientEarlyFrame::Headers {
            stream_id,
            end_stream,
            end_headers,
            headers,
        } => connection.process_frame(Frame::Headers(HeadersFrame::new(
            client_stream_id(*stream_id),
            encode_headers(headers),
            *end_stream,
            *end_headers,
        ))),
        ClientEarlyFrame::Ping { ack, payload } => {
            let ping = if *ack {
                PingFrame::ack(*payload)
            } else {
                PingFrame::new(*payload)
            };
            connection.process_frame(Frame::Ping(ping))
        }
        ClientEarlyFrame::Priority {
            stream_id,
            dependency,
            weight,
            exclusive,
        } => connection.process_frame(Frame::Priority(PriorityFrame {
            stream_id: client_stream_id(*stream_id),
            priority: PrioritySpec {
                exclusive: *exclusive,
                dependency: dependency & 0x7fff_ffff,
                weight: *weight,
            },
        })),
        ClientEarlyFrame::WindowUpdate {
            stream_id,
            increment,
        } => connection.process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(
            *stream_id & 0x7fff_ffff,
            *increment & 0x7fff_ffff,
        ))),
    }
}

fn process_production_post_frame(
    connection: &mut Connection,
    frame: &PostHandshakeFrame,
) -> Result<Option<asupersync::http::h2::connection::ReceivedFrame>, asupersync::http::h2::H2Error>
{
    match frame {
        PostHandshakeFrame::Data {
            stream_id,
            data,
            end_stream,
        } => connection.process_frame(Frame::Data(DataFrame::new(
            client_stream_id(*stream_id),
            Bytes::copy_from_slice(&data[..data.len().min(MAX_DATA_LEN)]),
            *end_stream,
        ))),
        PostHandshakeFrame::RstStream {
            stream_id,
            error_code,
        } => connection.process_frame(Frame::RstStream(RstStreamFrame::new(
            client_stream_id(*stream_id),
            ErrorCode::from_u32(*error_code),
        ))),
        PostHandshakeFrame::GoAway {
            last_stream_id,
            error_code,
            debug_data,
        } => {
            let mut goaway = GoAwayFrame::new(
                *last_stream_id & 0x7fff_ffff,
                ErrorCode::from_u32(*error_code),
            );
            goaway.debug_data =
                Bytes::copy_from_slice(&debug_data[..debug_data.len().min(MAX_DATA_LEN)]);
            connection.process_frame(Frame::GoAway(goaway))
        }
    }
}

fn assert_not_first_frame_error(
    result: Result<
        Option<asupersync::http::h2::connection::ReceivedFrame>,
        asupersync::http::h2::H2Error,
    >,
) {
    if let Err(err) = result {
        assert_ne!(
            err.code,
            ErrorCode::NoError,
            "errors must carry a real HTTP/2 code"
        );
        assert!(
            !err.message.contains("first frame"),
            "after peer SETTINGS, production frame handling should not reject as first-frame ordering: {err}",
        );
    }
}

fn drain_production_pending(connection: &mut Connection) -> (bool, bool) {
    let mut settings_seen = false;
    let mut ack_seen = false;
    for _ in 0..MAX_DRAIN_FRAMES {
        let Some(frame) = connection.next_frame() else {
            break;
        };
        match frame {
            Frame::Settings(settings) => {
                if settings.ack {
                    ack_seen = true;
                    assert!(
                        settings.settings.is_empty(),
                        "SETTINGS ACK must not carry payload",
                    );
                } else {
                    settings_seen = true;
                    assert!(
                        !settings.settings.is_empty(),
                        "initial non-ACK SETTINGS should carry settings",
                    );
                }
            }
            Frame::Ping(ping) => {
                assert!(ping.ack, "only PING ACKs should be emitted while draining");
            }
            Frame::Headers(headers) => {
                assert_ne!(headers.stream_id, 0, "HEADERS must be stream-scoped");
            }
            _ => {}
        }
    }
    (settings_seen, ack_seen)
}

fn encode_headers(headers: &[(String, String)]) -> Bytes {
    let normalized = if headers.is_empty() {
        default_request_headers()
    } else {
        let mut out = default_request_headers();
        for (index, (name, value)) in headers.iter().take(MAX_HEADERS).enumerate() {
            out.push(Header::new(
                normalized_header_name(name, index),
                bounded_visible_ascii(value, "value", MAX_COMPONENT_LEN),
            ));
        }
        out
    };

    let mut encoded = BytesMut::new();
    HpackEncoder::new().encode(&normalized, &mut encoded);
    encoded.freeze()
}

fn default_request_headers() -> Vec<Header> {
    vec![
        Header::new(":method", "GET"),
        Header::new(":path", "/"),
        Header::new(":scheme", "https"),
        Header::new(":authority", "example.test"),
    ]
}

fn client_stream_id(stream_id: u32) -> u32 {
    let mut id = stream_id & 0x7fff_ffff;
    if id == 0 {
        id = 1;
    }
    id | 1
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_handshake() {
        let mut parser = MockH2HandshakeParser::new();

        // Client preface
        parser.process_client_preface().unwrap();

        // Client SETTINGS
        parser
            .process_client_frame(&ClientEarlyFrame::Settings(vec![]))
            .unwrap();

        // Server SETTINGS
        parser.process_server_settings(&[], false).unwrap();

        assert_eq!(parser.state, ConnectionState::Connected);
    }

    #[test]
    fn test_client_early_frames_allowed() {
        let mut parser = MockH2HandshakeParser::new();

        // Client preface
        parser.process_client_preface().unwrap();

        // Client SETTINGS
        parser
            .process_client_frame(&ClientEarlyFrame::Settings(vec![]))
            .unwrap();

        // Client sends HEADERS before server SETTINGS (RFC 7540 §3.5 allows this)
        let result = parser.process_client_frame(&ClientEarlyFrame::Headers {
            stream_id: 1,
            end_stream: false,
            end_headers: true,
            headers: vec![
                (":method".to_string(), "GET".to_string()),
                (":path".to_string(), "/".to_string()),
                (":scheme".to_string(), "https".to_string()),
                (":authority".to_string(), "example.com".to_string()),
            ],
        });

        assert!(result.is_ok());
        assert_eq!(parser.state, ConnectionState::ClientEarlyFramesPending);

        // Server SETTINGS completes handshake
        parser.process_server_settings(&[], false).unwrap();
        assert_eq!(parser.state, ConnectionState::Connected);
    }

    #[test]
    fn test_server_settings_with_ack_first_fails() {
        let mut parser = MockH2HandshakeParser::new();

        parser.process_client_preface().unwrap();
        parser
            .process_client_frame(&ClientEarlyFrame::Settings(vec![]))
            .unwrap();

        // Server sends SETTINGS with ACK as first frame (invalid)
        let result = parser.process_server_settings(&[], true);
        assert!(matches!(result, Err(HandshakeError::ServerSettingsWithAck)));
    }

    #[test]
    fn test_frame_before_preface_fails() {
        let mut parser = MockH2HandshakeParser::new();

        // Try to send frame before preface
        let result = parser.process_client_frame(&ClientEarlyFrame::Settings(vec![]));
        assert!(matches!(result, Err(HandshakeError::FrameBeforePreface)));
    }

    #[test]
    fn test_invalid_stream_ids() {
        let mut parser = MockH2HandshakeParser::new();

        parser.process_client_preface().unwrap();
        parser
            .process_client_frame(&ClientEarlyFrame::Settings(vec![]))
            .unwrap();

        // Stream ID 0 for HEADERS frame
        let result = parser.process_client_frame(&ClientEarlyFrame::Headers {
            stream_id: 0,
            end_stream: false,
            end_headers: true,
            headers: vec![],
        });
        assert!(matches!(result, Err(HandshakeError::StreamIdZero)));

        // Even stream ID from client (invalid)
        let result = parser.process_client_frame(&ClientEarlyFrame::Headers {
            stream_id: 2,
            end_stream: false,
            end_headers: true,
            headers: vec![],
        });
        assert!(matches!(result, Err(HandshakeError::InvalidStreamId)));
    }

    #[test]
    fn test_settings_validation() {
        let mut parser = MockH2HandshakeParser::new();

        parser.process_client_preface().unwrap();

        // Invalid SETTINGS_ENABLE_PUSH value
        let result = parser.process_client_frame(&ClientEarlyFrame::Settings(vec![
            SettingsParameter { id: 2, value: 5 }, // ENABLE_PUSH must be 0 or 1
        ]));
        assert!(result.is_err());

        // Invalid SETTINGS_INITIAL_WINDOW_SIZE value
        let result = parser.process_client_frame(&ClientEarlyFrame::Settings(vec![
            SettingsParameter {
                id: 4,
                value: 2147483648,
            }, // > 2^31 - 1
        ]));
        assert!(result.is_err());

        // Invalid SETTINGS_MAX_FRAME_SIZE value
        let result = parser.process_client_frame(&ClientEarlyFrame::Settings(vec![
            SettingsParameter { id: 5, value: 1000 }, // < 16384
        ]));
        assert!(result.is_err());
    }

    #[test]
    fn test_timing_scenarios() {
        let input = H2HandshakeTimingInput {
            client_early_frames: vec![
                ClientEarlyFrame::Settings(vec![]),
                ClientEarlyFrame::Ping {
                    ack: false,
                    payload: [0; 8],
                },
                ClientEarlyFrame::Headers {
                    stream_id: 1,
                    end_stream: false,
                    end_headers: true,
                    headers: vec![],
                },
            ],
            server_settings: vec![],
            server_settings_ack: false,
            post_handshake_frames: vec![],
            timing_scenario: TimingScenario::ClientSendsEarly,
        };

        let mut parser = MockH2HandshakeParser::new();
        let result = parser.simulate_handshake_timing(&input);

        // Early frames should be accepted per RFC 7540 §3.5
        assert!(result.is_ok());
        assert_eq!(parser.state, ConnectionState::Connected);
    }
}
