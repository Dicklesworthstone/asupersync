#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::collections::HashMap;

/// Test input structure for pseudo-header ordering scenarios
#[derive(Arbitrary, Clone, Debug)]
struct PseudoHeaderOrderInput {
    headers: Vec<HeaderEntry>,              // Headers in the order they appear
    stream_id: u32,                        // Stream ID for the request
    end_headers: bool,                     // Whether to set END_HEADERS flag
    end_stream: bool,                      // Whether to set END_STREAM flag
    preceding_frames: Vec<PrecedingFrame>, // Frames before HEADERS
    follow_up_frames: Vec<FollowUpFrame>,  // Frames after HEADERS
}

/// A single header entry (pseudo-header or regular header)
#[derive(Arbitrary, Clone, Debug)]
enum HeaderEntry {
    PseudoHeader(PseudoHeaderType, String), // Pseudo-header with value
    RegularHeader(String, String),          // Regular header name and value
}

/// Types of pseudo-headers
#[derive(Arbitrary, Clone, Debug)]
enum PseudoHeaderType {
    Method,    // :method
    Scheme,    // :scheme
    Authority, // :authority
    Path,      // :path
}

/// Frames that can precede the HEADERS frame
#[derive(Arbitrary, Clone, Debug)]
enum PrecedingFrame {
    Settings { parameters: Vec<(u16, u32)> },
    WindowUpdate { stream_id: u32, increment: u32 },
    Priority { stream_id: u32, dependency: u32, weight: u8, exclusive: bool },
}

/// Frames that can follow the HEADERS frame
#[derive(Arbitrary, Clone, Debug)]
enum FollowUpFrame {
    Data { stream_id: u32, data: Vec<u8>, end_stream: bool },
    Headers { stream_id: u32, end_headers: bool, end_stream: bool },
    RstStream { stream_id: u32, error_code: u32 },
    WindowUpdate { stream_id: u32, increment: u32 },
}

/// Mock connection state to track pseudo-header ordering validation
struct MockPseudoHeaderOrderConnection {
    stream_states: HashMap<u32, StreamState>,
    connection_error: Option<u32>,
    protocol_violations: Vec<String>,
    ordering_violations_detected: Vec<OrderingViolationInfo>,
    last_stream_error: Option<u32>,
}

/// Information about pseudo-header ordering violations detected
#[derive(Clone, Debug)]
struct OrderingViolationInfo {
    stream_id: u32,
    violation_type: OrderingViolationType,
    pseudo_header: String,
    previous_regular_header: String,
}

#[derive(Clone, Debug, PartialEq)]
enum OrderingViolationType {
    PseudoAfterRegular,       // Pseudo-header found after regular header
    DuplicatePseudoHeader,    // Same pseudo-header appears multiple times
    UnknownPseudoHeader,      // Pseudo-header not in allowed set
    MissingRequiredPseudo,    // Required pseudo-header missing (:method, :scheme, :path)
}

/// Track the state of each stream for header ordering validation
#[derive(Clone, Debug)]
struct StreamState {
    headers_started: bool,
    regular_headers_started: bool,
    pseudo_headers_seen: HashMap<String, String>,
    last_regular_header: Option<String>,
    ended_remotely: bool,
    ordering_violation_detected: bool,
}

/// HTTP/2 frame types
const FRAME_TYPE_HEADERS: u8 = 0x1;
const FRAME_TYPE_PRIORITY: u8 = 0x2;
const FRAME_TYPE_RST_STREAM: u8 = 0x3;
const FRAME_TYPE_SETTINGS: u8 = 0x4;
const FRAME_TYPE_WINDOW_UPDATE: u8 = 0x8;
const FRAME_TYPE_DATA: u8 = 0x0;

/// HTTP/2 frame flags
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;

/// Error codes
const PROTOCOL_ERROR: u32 = 0x1;

impl PseudoHeaderType {
    fn to_name(&self) -> &'static str {
        match self {
            PseudoHeaderType::Method => ":method",
            PseudoHeaderType::Scheme => ":scheme",
            PseudoHeaderType::Authority => ":authority",
            PseudoHeaderType::Path => ":path",
        }
    }
}

impl MockPseudoHeaderOrderConnection {
    fn new() -> Self {
        Self {
            stream_states: HashMap::new(),
            connection_error: None,
            protocol_violations: Vec::new(),
            ordering_violations_detected: Vec::new(),
            last_stream_error: None,
        }
    }

    /// Process a frame and validate pseudo-header ordering
    fn process_frame(&mut self, frame_type: u8, stream_id: u32, flags: u8, payload: &[u8]) {
        match frame_type {
            FRAME_TYPE_HEADERS => {
                self.process_headers_frame(stream_id, flags, payload);
            }
            FRAME_TYPE_PRIORITY => {
                self.process_priority_frame(stream_id, payload);
            }
            FRAME_TYPE_RST_STREAM => {
                self.process_rst_stream_frame(stream_id, payload);
            }
            FRAME_TYPE_SETTINGS => {
                self.process_settings_frame(payload);
            }
            FRAME_TYPE_WINDOW_UPDATE => {
                self.process_window_update_frame(stream_id, payload);
            }
            FRAME_TYPE_DATA => {
                self.process_data_frame(stream_id, flags, payload);
            }
            _ => {
                // Unknown frame type - should be ignored per spec
            }
        }
    }

    fn process_headers_frame(&mut self, stream_id: u32, flags: u8, payload: &[u8]) {
        // HEADERS frames MUST have non-zero stream ID for requests
        if stream_id == 0 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations.push("HEADERS frame with stream ID 0".to_string());
            return;
        }

        // Get or create stream state
        let stream_state = self.stream_states.entry(stream_id).or_insert(StreamState {
            headers_started: false,
            regular_headers_started: false,
            pseudo_headers_seen: HashMap::new(),
            last_regular_header: None,
            ended_remotely: false,
            ordering_violation_detected: false,
        });

        stream_state.headers_started = true;

        let end_stream = (flags & FLAG_END_STREAM) != 0;
        let _end_headers = (flags & FLAG_END_HEADERS) != 0;

        if end_stream {
            stream_state.ended_remotely = true;
        }

        // Parse the headers from the payload and validate ordering
        // In a real implementation, this would involve HPACK decoding
        // For this fuzz target, we'll simulate the parsing
        let header_validation_result = self.extract_and_validate_header_ordering(stream_id, payload);

        if let Err(violation_info) = header_validation_result {
            // Invalid header ordering detected
            stream_state.ordering_violation_detected = true;

            self.ordering_violations_detected.push(violation_info.clone());

            // Per RFC 7540 §8.1.2.1, invalid pseudo-header ordering is PROTOCOL_ERROR
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations.push(format!(
                "Invalid pseudo-header ordering on stream {}: {:?}",
                stream_id, violation_info
            ));
            return; // Stop processing after ordering violation
        }
    }

    fn extract_and_validate_header_ordering(&mut self, stream_id: u32, payload: &[u8]) -> Result<(), OrderingViolationInfo> {
        // In a real implementation, this would be HPACK decoding
        // For fuzz testing, we'll simulate extracting headers from the payload

        // Get the stream state
        let stream_state = self.stream_states.get_mut(&stream_id).unwrap();

        // For simulation, we'll parse the payload as a simple representation of headers
        // In practice, this would be much more complex with HPACK
        let headers = self.simulate_header_parsing(payload);

        for (name, value) in &headers {
            // Check if this is a pseudo-header
            if name.starts_with(':') {
                // This is a pseudo-header
                if stream_state.regular_headers_started {
                    // CRITICAL: Pseudo-header found after regular headers - PROTOCOL_ERROR
                    let last_regular = stream_state.last_regular_header
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string());

                    return Err(OrderingViolationInfo {
                        stream_id,
                        violation_type: OrderingViolationType::PseudoAfterRegular,
                        pseudo_header: name.clone(),
                        previous_regular_header: last_regular,
                    });
                }

                // Check for duplicate pseudo-headers
                if stream_state.pseudo_headers_seen.contains_key(name) {
                    return Err(OrderingViolationInfo {
                        stream_id,
                        violation_type: OrderingViolationType::DuplicatePseudoHeader,
                        pseudo_header: name.clone(),
                        previous_regular_header: String::new(),
                    });
                }

                // Validate that this is a known pseudo-header
                if !is_valid_pseudo_header(name) {
                    return Err(OrderingViolationInfo {
                        stream_id,
                        violation_type: OrderingViolationType::UnknownPseudoHeader,
                        pseudo_header: name.clone(),
                        previous_regular_header: String::new(),
                    });
                }

                // Record this pseudo-header
                stream_state.pseudo_headers_seen.insert(name.clone(), value.clone());
            } else {
                // This is a regular header
                stream_state.regular_headers_started = true;
                stream_state.last_regular_header = Some(name.clone());
            }
        }

        Ok(())
    }

    fn simulate_header_parsing(&self, payload: &[u8]) -> Vec<(String, String)> {
        // Simple simulation of header parsing from payload
        // In reality, this would be HPACK decoding

        let mut headers = Vec::new();

        // For testing, we'll try to interpret the payload as headers
        if payload.is_empty() {
            return headers;
        }

        // Simple approach: split by newlines and parse as name:value
        let payload_str = String::from_utf8_lossy(payload);
        for line in payload_str.lines() {
            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim().to_string();
                let value = line[colon_pos + 1..].trim().to_string();
                if !name.is_empty() {
                    headers.push((name, value));
                }
            } else if !line.trim().is_empty() {
                // Treat as header without value
                headers.push((line.trim().to_string(), String::new()));
            }
        }

        headers
    }

    fn process_priority_frame(&mut self, stream_id: u32, payload: &[u8]) {
        if payload.len() != 5 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations.push("PRIORITY frame with invalid length".to_string());
            return;
        }

        if stream_id == 0 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations.push("PRIORITY frame with stream ID 0".to_string());
            return;
        }

        // PRIORITY frames don't affect pseudo-header ordering
    }

    fn process_rst_stream_frame(&mut self, stream_id: u32, payload: &[u8]) {
        if payload.len() != 4 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations.push("RST_STREAM frame with invalid length".to_string());
            return;
        }

        if stream_id == 0 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations.push("RST_STREAM frame with stream ID 0".to_string());
            return;
        }

        // Reset stream state
        if let Some(stream_state) = self.stream_states.get_mut(&stream_id) {
            stream_state.ended_remotely = true;
        }
    }

    fn process_settings_frame(&mut self, payload: &[u8]) {
        if payload.len() % 6 != 0 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations.push("SETTINGS frame with invalid length".to_string());
            return;
        }
        // SETTINGS frames don't affect pseudo-header ordering
    }

    fn process_window_update_frame(&mut self, _stream_id: u32, payload: &[u8]) {
        if payload.len() != 4 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations.push("WINDOW_UPDATE frame with invalid length".to_string());
            return;
        }

        let increment = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        if increment == 0 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations.push("WINDOW_UPDATE with zero increment".to_string());
        }

        // WINDOW_UPDATE doesn't affect pseudo-header ordering
    }

    fn process_data_frame(&mut self, stream_id: u32, _flags: u8, _payload: &[u8]) {
        if stream_id == 0 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations.push("DATA frame with stream ID 0".to_string());
        }

        // DATA frames don't affect pseudo-header ordering
    }

    fn has_protocol_error(&self) -> bool {
        self.connection_error.is_some()
    }

    fn get_error_code(&self) -> Option<u32> {
        self.connection_error
    }

    fn get_violations(&self) -> &[String] {
        &self.protocol_violations
    }

    fn get_ordering_violations(&self) -> &[OrderingViolationInfo] {
        &self.ordering_violations_detected
    }

    fn count_pseudo_after_regular_violations(&self) -> usize {
        self.ordering_violations_detected.iter()
            .filter(|info| info.violation_type == OrderingViolationType::PseudoAfterRegular)
            .count()
    }

    fn count_duplicate_pseudo_violations(&self) -> usize {
        self.ordering_violations_detected.iter()
            .filter(|info| info.violation_type == OrderingViolationType::DuplicatePseudoHeader)
            .count()
    }

    fn count_unknown_pseudo_violations(&self) -> usize {
        self.ordering_violations_detected.iter()
            .filter(|info| info.violation_type == OrderingViolationType::UnknownPseudoHeader)
            .count()
    }
}

/// Check if a header name is a valid pseudo-header per RFC 7540 §8.1.2.1
fn is_valid_pseudo_header(name: &str) -> bool {
    matches!(name, ":method" | ":scheme" | ":authority" | ":path")
}

/// Check if header ordering should be invalid
fn has_invalid_ordering(headers: &[HeaderEntry]) -> bool {
    let mut regular_header_seen = false;

    for header in headers {
        match header {
            HeaderEntry::PseudoHeader(_, _) => {
                if regular_header_seen {
                    return true; // Pseudo-header after regular header
                }
            }
            HeaderEntry::RegularHeader(_, _) => {
                regular_header_seen = true;
            }
        }
    }

    false
}

/// Send a preceding frame to set up connection state
fn send_preceding_frame(conn: &mut MockPseudoHeaderOrderConnection, frame: &PrecedingFrame) {
    match frame {
        PrecedingFrame::Settings { parameters } => {
            let mut payload = Vec::new();
            for (id, value) in parameters {
                payload.extend_from_slice(&id.to_be_bytes());
                payload.extend_from_slice(&value.to_be_bytes());
            }
            conn.process_frame(FRAME_TYPE_SETTINGS, 0, 0, &payload);
        }
        PrecedingFrame::WindowUpdate { stream_id, increment } => {
            let payload = increment.to_be_bytes().to_vec();
            conn.process_frame(FRAME_TYPE_WINDOW_UPDATE, *stream_id, 0, &payload);
        }
        PrecedingFrame::Priority { stream_id, dependency, weight, exclusive } => {
            let mut payload = Vec::new();
            let dep_field = if *exclusive { *dependency | 0x80000000 } else { *dependency };
            payload.extend_from_slice(&dep_field.to_be_bytes());
            payload.push(*weight);
            conn.process_frame(FRAME_TYPE_PRIORITY, *stream_id, 0, &payload);
        }
    }
}

/// Send a follow-up frame after the HEADERS frame
fn send_follow_up_frame(conn: &mut MockPseudoHeaderOrderConnection, frame: &FollowUpFrame) {
    match frame {
        FollowUpFrame::Data { stream_id, data, end_stream } => {
            let flags = if *end_stream { FLAG_END_STREAM } else { 0 };
            conn.process_frame(FRAME_TYPE_DATA, *stream_id, flags, data);
        }
        FollowUpFrame::Headers { stream_id, end_headers, end_stream } => {
            let mut flags = 0;
            if *end_headers { flags |= FLAG_END_HEADERS; }
            if *end_stream { flags |= FLAG_END_STREAM; }
            conn.process_frame(FRAME_TYPE_HEADERS, *stream_id, flags, b"headers");
        }
        FollowUpFrame::RstStream { stream_id, error_code } => {
            let payload = error_code.to_be_bytes().to_vec();
            conn.process_frame(FRAME_TYPE_RST_STREAM, *stream_id, 0, &payload);
        }
        FollowUpFrame::WindowUpdate { stream_id, increment } => {
            let payload = increment.to_be_bytes().to_vec();
            conn.process_frame(FRAME_TYPE_WINDOW_UPDATE, *stream_id, 0, &payload);
        }
    }
}

/// Convert header entries to a simulated payload for testing
fn headers_to_payload(headers: &[HeaderEntry]) -> Vec<u8> {
    let mut payload = Vec::new();

    for header in headers {
        match header {
            HeaderEntry::PseudoHeader(pseudo_type, value) => {
                let line = format!("{}:{}\n", pseudo_type.to_name(), value);
                payload.extend_from_slice(line.as_bytes());
            }
            HeaderEntry::RegularHeader(name, value) => {
                let line = format!("{}:{}\n", name, value);
                payload.extend_from_slice(line.as_bytes());
            }
        }
    }

    payload
}

fuzz_target!(|input: PseudoHeaderOrderInput| {
    // Limit input sizes to prevent excessive memory usage
    if input.headers.len() > 100 ||
       input.preceding_frames.len() > 50 ||
       input.follow_up_frames.len() > 50 {
        return;
    }

    // Ensure stream ID is valid (non-zero for client-initiated streams)
    let stream_id = if input.stream_id == 0 || input.stream_id > 0x7FFFFFFF {
        1
    } else {
        input.stream_id | 1 // Ensure odd (client-initiated)
    };

    let mut conn = MockPseudoHeaderOrderConnection::new();

    // Send preceding frames to set up connection state
    for frame in &input.preceding_frames {
        send_preceding_frame(&mut conn, frame);
        if conn.has_protocol_error() {
            // Stop if we hit a protocol error from setup frames
            return;
        }
    }

    // Determine if the header ordering should be invalid
    let should_be_invalid = has_invalid_ordering(&input.headers);

    // Create HEADERS frame payload with the headers
    let payload = headers_to_payload(&input.headers);

    let mut flags = 0;
    if input.end_headers { flags |= FLAG_END_HEADERS; }
    if input.end_stream { flags |= FLAG_END_STREAM; }

    // Send the HEADERS frame with potentially invalid pseudo-header ordering
    conn.process_frame(FRAME_TYPE_HEADERS, stream_id, flags, &payload);

    if should_be_invalid {
        // CRITICAL: Invalid pseudo-header ordering MUST be rejected
        assert!(
            conn.has_protocol_error(),
            "Invalid pseudo-header ordering must cause protocol error. \
             Headers: {:?}, END_HEADERS: {}, END_STREAM: {}, Violations: {:?}",
            input.headers,
            input.end_headers,
            input.end_stream,
            conn.get_violations()
        );

        assert_eq!(
            conn.get_error_code(),
            Some(PROTOCOL_ERROR),
            "Invalid pseudo-header ordering must result in PROTOCOL_ERROR (0x1), got {:?}. \
             Headers: {:?}, Violations: {:?}",
            conn.get_error_code(),
            input.headers,
            conn.get_violations()
        );

        // Verify we detected the ordering violation
        assert!(
            !conn.get_ordering_violations().is_empty(),
            "Expected ordering violation to be detected and recorded"
        );

    } else {
        // Valid ordering should not cause error (unless other validation fails)
        // Note: We might still get errors for other reasons (malformed headers, etc.)
        // but not specifically for ordering
        if conn.has_protocol_error() {
            // Check that the error is not specifically for ordering
            let violations = conn.get_violations();
            for violation in violations {
                assert!(
                    !violation.contains("ordering"),
                    "Valid ordering should not cause ordering-related error: {}",
                    violation
                );
            }
        }
    }

    // Send follow-up frames to test continued operation
    if !conn.has_protocol_error() {
        for frame in &input.follow_up_frames {
            send_follow_up_frame(&mut conn, frame);
            if conn.has_protocol_error() {
                break;
            }
        }
    }

    // Test specific pseudo-header ordering scenarios
    test_pseudo_header_ordering_scenarios(&input);
});

/// Test specific pseudo-header ordering scenarios
fn test_pseudo_header_ordering_scenarios(_input: &PseudoHeaderOrderInput) {
    // Scenario 1: Pseudo-header after regular header (MUST be PROTOCOL_ERROR)
    {
        let mut conn = MockPseudoHeaderOrderConnection::new();
        let payload = b"host:example.com\n:method:GET\n";
        conn.process_frame(FRAME_TYPE_HEADERS, 1, FLAG_END_HEADERS, payload);

        assert!(
            conn.has_protocol_error(),
            "Pseudo-header after regular header must be PROTOCOL_ERROR per RFC 7540 §8.1.2.1"
        );
        assert_eq!(conn.count_pseudo_after_regular_violations(), 1);
    }

    // Scenario 2: All pseudo-headers before regular headers (valid)
    {
        let mut conn = MockPseudoHeaderOrderConnection::new();
        let payload = b":method:GET\n:scheme:https\n:path:/test\nhost:example.com\n";
        conn.process_frame(FRAME_TYPE_HEADERS, 1, FLAG_END_HEADERS, payload);

        assert!(
            !conn.has_protocol_error(),
            "Valid pseudo-header ordering should not cause PROTOCOL_ERROR"
        );
    }

    // Scenario 3: Mixed ordering - pseudo, regular, pseudo (invalid)
    {
        let mut conn = MockPseudoHeaderOrderConnection::new();
        let payload = b":method:GET\nhost:example.com\n:scheme:https\n";
        conn.process_frame(FRAME_TYPE_HEADERS, 1, FLAG_END_HEADERS, payload);

        assert!(
            conn.has_protocol_error(),
            "Mixed pseudo/regular/pseudo ordering must be PROTOCOL_ERROR"
        );
        assert_eq!(conn.count_pseudo_after_regular_violations(), 1);
    }

    // Scenario 4: Duplicate pseudo-headers
    {
        let mut conn = MockPseudoHeaderOrderConnection::new();
        let payload = b":method:GET\n:method:POST\n";
        conn.process_frame(FRAME_TYPE_HEADERS, 1, FLAG_END_HEADERS, payload);

        assert!(
            conn.has_protocol_error(),
            "Duplicate pseudo-headers must be PROTOCOL_ERROR"
        );
        assert_eq!(conn.count_duplicate_pseudo_violations(), 1);
    }

    // Scenario 5: Unknown pseudo-header
    {
        let mut conn = MockPseudoHeaderOrderConnection::new();
        let payload = b":method:GET\n:unknown:value\n";
        conn.process_frame(FRAME_TYPE_HEADERS, 1, FLAG_END_HEADERS, payload);

        assert!(
            conn.has_protocol_error(),
            "Unknown pseudo-header must be PROTOCOL_ERROR"
        );
        assert_eq!(conn.count_unknown_pseudo_violations(), 1);
    }

    // Scenario 6: Only regular headers (valid - pseudo-headers may be optional)
    {
        let mut conn = MockPseudoHeaderOrderConnection::new();
        let payload = b"host:example.com\nuser-agent:test\n";
        conn.process_frame(FRAME_TYPE_HEADERS, 1, FLAG_END_HEADERS, payload);

        // This should be valid (pseudo-headers may be optional for some frame types)
        // The key is that there's no ordering violation
        if conn.has_protocol_error() {
            // If there's an error, it should not be for ordering
            let violations = conn.get_violations();
            for violation in violations {
                assert!(
                    !violation.contains("ordering"),
                    "Regular headers only should not cause ordering error"
                );
            }
        }
    }

    // Scenario 7: Only pseudo-headers (valid)
    {
        let mut conn = MockPseudoHeaderOrderConnection::new();
        let payload = b":method:GET\n:scheme:https\n:authority:example.com\n:path:/test\n";
        conn.process_frame(FRAME_TYPE_HEADERS, 1, FLAG_END_HEADERS, payload);

        assert!(
            !conn.has_protocol_error(),
            "Only pseudo-headers should be valid"
        );
    }

    // Scenario 8: Complex invalid ordering
    {
        let mut conn = MockPseudoHeaderOrderConnection::new();
        let payload = b":method:GET\nhost:example.com\ncontent-type:text/plain\n:path:/test\n";
        conn.process_frame(FRAME_TYPE_HEADERS, 1, FLAG_END_HEADERS, payload);

        assert!(
            conn.has_protocol_error(),
            "Pseudo-header after multiple regular headers must be PROTOCOL_ERROR"
        );
        assert_eq!(conn.count_pseudo_after_regular_violations(), 1);
    }

    // Scenario 9: Empty headers (edge case)
    {
        let mut conn = MockPseudoHeaderOrderConnection::new();
        let payload = b"";
        conn.process_frame(FRAME_TYPE_HEADERS, 1, FLAG_END_HEADERS, payload);

        // Empty headers might be valid or invalid depending on context
        // The key is no ordering violation
        assert_eq!(conn.count_pseudo_after_regular_violations(), 0);
    }

    // Scenario 10: Case sensitivity test
    {
        let mut conn = MockPseudoHeaderOrderConnection::new();
        let payload = b":METHOD:GET\nhost:example.com\n"; // Uppercase pseudo-header
        conn.process_frame(FRAME_TYPE_HEADERS, 1, FLAG_END_HEADERS, payload);

        // :METHOD is not a valid pseudo-header (:method is)
        assert!(
            conn.has_protocol_error(),
            "Invalid pseudo-header case should be rejected"
        );
    }

    // Scenario 11: Valid request headers
    let valid_requests = [
        b":method:GET\n:scheme:https\n:authority:example.com\n:path:/\nhost:example.com\n",
        b":method:POST\n:scheme:http\n:path:/submit\ncontent-type:application/json\n",
        b":method:OPTIONS\n:scheme:https\n:authority:api.example.com\n:path:*\norigin:https://example.com\n",
    ];

    for (i, payload) in valid_requests.iter().enumerate() {
        let mut conn = MockPseudoHeaderOrderConnection::new();
        conn.process_frame(FRAME_TYPE_HEADERS, 1, FLAG_END_HEADERS, payload);

        assert!(
            !conn.has_protocol_error(),
            "Valid request headers #{} should not cause PROTOCOL_ERROR", i
        );
        assert_eq!(conn.count_pseudo_after_regular_violations(), 0);
    }

    // Scenario 12: Invalid request headers with ordering violations
    let invalid_requests = [
        b"host:example.com\n:method:GET\n", // Regular before pseudo
        b":method:GET\nhost:example.com\n:scheme:https\n", // Pseudo after regular
        b"content-type:text/plain\n:method:POST\n:path:/submit\n", // Multiple violations
    ];

    for (i, payload) in invalid_requests.iter().enumerate() {
        let mut conn = MockPseudoHeaderOrderConnection::new();
        conn.process_frame(FRAME_TYPE_HEADERS, 1, FLAG_END_HEADERS, payload);

        assert!(
            conn.has_protocol_error(),
            "Invalid request headers #{} must cause PROTOCOL_ERROR", i
        );
        assert!(conn.count_pseudo_after_regular_violations() >= 1);
    }
}