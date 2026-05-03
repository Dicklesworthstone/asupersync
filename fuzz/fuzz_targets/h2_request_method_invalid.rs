#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// Test input structure for invalid :method pseudo-header scenarios
#[derive(Arbitrary, Clone, Debug)]
struct InvalidMethodInput {
    method: String,                        // The :method value to test
    other_headers: Vec<(String, String)>,  // Other headers to include
    stream_id: u32,                        // Stream ID for the request
    end_headers: bool,                     // Whether to set END_HEADERS flag
    end_stream: bool,                      // Whether to set END_STREAM flag
    preceding_frames: Vec<PrecedingFrame>, // Frames before HEADERS
    follow_up_frames: Vec<FollowUpFrame>,  // Frames after HEADERS
}

/// Frames that can precede the HEADERS frame
#[derive(Arbitrary, Clone, Debug)]
enum PrecedingFrame {
    Settings {
        parameters: Vec<(u16, u32)>,
    },
    WindowUpdate {
        stream_id: u32,
        increment: u32,
    },
    Priority {
        stream_id: u32,
        dependency: u32,
        weight: u8,
        exclusive: bool,
    },
}

/// Frames that can follow the HEADERS frame
#[derive(Arbitrary, Clone, Debug)]
enum FollowUpFrame {
    Data {
        stream_id: u32,
        data: Vec<u8>,
        end_stream: bool,
    },
    Headers {
        stream_id: u32,
        end_headers: bool,
        end_stream: bool,
    },
    RstStream {
        stream_id: u32,
        error_code: u32,
    },
    WindowUpdate {
        stream_id: u32,
        increment: u32,
    },
}

/// Mock connection state to track :method validation
struct MockInvalidMethodConnection {
    stream_states: HashMap<u32, StreamState>,
    connection_error: Option<u32>,
    protocol_violations: Vec<String>,
    invalid_methods_detected: Vec<InvalidMethodInfo>,
    last_stream_error: Option<u32>,
}

/// Information about invalid :method pseudo-headers detected
#[derive(Clone, Debug)]
struct InvalidMethodInfo {
    stream_id: u32,
    method: String,
    violation_type: MethodViolationType,
}

#[derive(Clone, Debug, PartialEq)]
enum MethodViolationType {
    Empty,             // Empty method string
    ControlCharacters, // Contains control characters (0x00-0x1F, 0x7F)
    InvalidCharacters, // Contains invalid characters per HTTP method rules
    WhitespaceOrCRLF,  // Contains whitespace, CR, or LF
}

/// Track the state of each stream
#[derive(Clone, Debug)]
struct StreamState {
    headers_received: bool,
    method_validated: bool,
    ended_remotely: bool,
    invalid_method_detected: bool,
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
const STREAM_CLOSED: u32 = 0x5;

impl MockInvalidMethodConnection {
    fn new() -> Self {
        Self {
            stream_states: HashMap::new(),
            connection_error: None,
            protocol_violations: Vec::new(),
            invalid_methods_detected: Vec::new(),
            last_stream_error: None,
        }
    }

    /// Process a frame and validate :method pseudo-header
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
            self.protocol_violations
                .push("HEADERS frame with stream ID 0".to_string());
            return;
        }

        let end_stream = (flags & FLAG_END_STREAM) != 0;
        let _end_headers = (flags & FLAG_END_HEADERS) != 0;

        // Parse the pseudo-headers from the payload first (before accessing stream state)
        // In a real implementation, this would involve HPACK decoding
        // For this fuzz target, we'll simulate the parsing
        let method_validation_result = self.extract_and_validate_method(payload);

        // Get or create stream state
        let stream_state = self.stream_states.entry(stream_id).or_insert(StreamState {
            headers_received: false,
            method_validated: false,
            ended_remotely: false,
            invalid_method_detected: false,
        });

        stream_state.headers_received = true;

        if end_stream {
            stream_state.ended_remotely = true;
        }

        match method_validation_result {
            Ok(_method) => {
                // Method is valid
                stream_state.method_validated = true;
                // Continue processing normally
            }
            Err((method, violation_type)) => {
                // Invalid method detected
                stream_state.invalid_method_detected = true;

                self.invalid_methods_detected.push(InvalidMethodInfo {
                    stream_id,
                    method: method.clone(),
                    violation_type: violation_type.clone(),
                });

                // Per RFC 7540 §8.1.2, invalid :method should result in stream error
                // or connection error depending on severity
                match violation_type {
                    MethodViolationType::ControlCharacters
                    | MethodViolationType::WhitespaceOrCRLF => {
                        // These are serious protocol violations - connection error
                        self.connection_error = Some(PROTOCOL_ERROR);
                        self.protocol_violations.push(format!(
                            "Invalid :method with control characters on stream {}: {:?}",
                            stream_id, method
                        ));
                    }
                    MethodViolationType::Empty | MethodViolationType::InvalidCharacters => {
                        // These might be stream-level errors depending on implementation
                        self.last_stream_error = Some(PROTOCOL_ERROR);
                        self.protocol_violations.push(format!(
                            "Invalid :method on stream {}: {:?}",
                            stream_id, method
                        ));
                        // For this test, we'll treat as connection error for simplicity
                        self.connection_error = Some(PROTOCOL_ERROR);
                    }
                }
                return; // Stop processing after invalid method
            }
        }
    }

    fn extract_and_validate_method(
        &self,
        payload: &[u8],
    ) -> Result<String, (String, MethodViolationType)> {
        // In a real implementation, this would be HPACK decoding
        // For fuzz testing, we'll simulate extracting the :method pseudo-header

        // Look for patterns that might represent a :method header
        // This is simplified - real HPACK would be more complex

        // For this simulation, we'll treat the payload as containing the method
        // if it starts with certain patterns, otherwise use a default
        let method = if payload.is_empty() {
            String::new()
        } else if payload.len() > 100 {
            // Limit method length for testing
            String::from_utf8_lossy(&payload[..100]).to_string()
        } else {
            String::from_utf8_lossy(payload).to_string()
        };

        self.validate_method(&method)
    }

    fn validate_method(&self, method: &str) -> Result<String, (String, MethodViolationType)> {
        // CRITICAL: Validate :method pseudo-header per RFC 7540 §8.1.2
        // The :method pseudo-header field includes the HTTP method

        // Rule 1: Method MUST NOT be empty
        if method.is_empty() {
            return Err((method.to_string(), MethodViolationType::Empty));
        }

        // Rule 2: Method MUST NOT contain control characters (0x00-0x1F, 0x7F)
        // Per RFC 7230 §3.2.6, HTTP method is a token
        for ch in method.chars() {
            let code = ch as u32;
            if code <= 0x1F || code == 0x7F {
                return Err((method.to_string(), MethodViolationType::ControlCharacters));
            }
        }

        // Rule 3: Method MUST NOT contain whitespace, CR, or LF
        // These are particularly problematic for HTTP parsing
        if method.contains(' ')
            || method.contains('\t')
            || method.contains('\r')
            || method.contains('\n')
        {
            return Err((method.to_string(), MethodViolationType::WhitespaceOrCRLF));
        }

        // Rule 4: Method should only contain valid token characters
        // Per RFC 7230 §3.2.6: token = 1*tchar
        // tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
        //         "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
        for ch in method.chars() {
            if !is_valid_token_char(ch) {
                return Err((method.to_string(), MethodViolationType::InvalidCharacters));
            }
        }

        // If we reach here, the method is valid
        Ok(method.to_string())
    }

    fn process_priority_frame(&mut self, stream_id: u32, payload: &[u8]) {
        if payload.len() != 5 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("PRIORITY frame with invalid length".to_string());
            return;
        }

        if stream_id == 0 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("PRIORITY frame with stream ID 0".to_string());
            return;
        }

        // PRIORITY frames don't affect :method validation
    }

    fn process_rst_stream_frame(&mut self, stream_id: u32, payload: &[u8]) {
        if payload.len() != 4 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("RST_STREAM frame with invalid length".to_string());
            return;
        }

        if stream_id == 0 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("RST_STREAM frame with stream ID 0".to_string());
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
            self.protocol_violations
                .push("SETTINGS frame with invalid length".to_string());
            return;
        }
        // SETTINGS frames don't affect :method validation
    }

    fn process_window_update_frame(&mut self, _stream_id: u32, payload: &[u8]) {
        if payload.len() != 4 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("WINDOW_UPDATE frame with invalid length".to_string());
            return;
        }

        let increment = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        if increment == 0 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("WINDOW_UPDATE with zero increment".to_string());
        }

        // WINDOW_UPDATE doesn't affect :method validation
    }

    fn process_data_frame(&mut self, stream_id: u32, _flags: u8, _payload: &[u8]) {
        if stream_id == 0 {
            self.connection_error = Some(PROTOCOL_ERROR);
            self.protocol_violations
                .push("DATA frame with stream ID 0".to_string());
        }

        // DATA frames don't affect :method validation
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

    fn get_invalid_methods(&self) -> &[InvalidMethodInfo] {
        &self.invalid_methods_detected
    }

    fn count_empty_methods(&self) -> usize {
        self.invalid_methods_detected
            .iter()
            .filter(|info| info.violation_type == MethodViolationType::Empty)
            .count()
    }

    fn count_control_char_methods(&self) -> usize {
        self.invalid_methods_detected
            .iter()
            .filter(|info| info.violation_type == MethodViolationType::ControlCharacters)
            .count()
    }

    fn count_whitespace_methods(&self) -> usize {
        self.invalid_methods_detected
            .iter()
            .filter(|info| info.violation_type == MethodViolationType::WhitespaceOrCRLF)
            .count()
    }

    fn count_invalid_char_methods(&self) -> usize {
        self.invalid_methods_detected
            .iter()
            .filter(|info| info.violation_type == MethodViolationType::InvalidCharacters)
            .count()
    }
}

/// Check if a character is valid in an HTTP token per RFC 7230 §3.2.6
fn is_valid_token_char(ch: char) -> bool {
    match ch {
        // ALPHA
        'A'..='Z' | 'a'..='z' => true,
        // DIGIT
        '0'..='9' => true,
        // Special characters allowed in tokens
        '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '.' | '^' | '_' | '`' | '|'
        | '~' => true,
        // Everything else is invalid
        _ => false,
    }
}

/// Send a preceding frame to set up connection state
fn send_preceding_frame(conn: &mut MockInvalidMethodConnection, frame: &PrecedingFrame) {
    match frame {
        PrecedingFrame::Settings { parameters } => {
            let mut payload = Vec::new();
            for (id, value) in parameters {
                payload.extend_from_slice(&id.to_be_bytes());
                payload.extend_from_slice(&value.to_be_bytes());
            }
            conn.process_frame(FRAME_TYPE_SETTINGS, 0, 0, &payload);
        }
        PrecedingFrame::WindowUpdate {
            stream_id,
            increment,
        } => {
            let payload = increment.to_be_bytes().to_vec();
            conn.process_frame(FRAME_TYPE_WINDOW_UPDATE, *stream_id, 0, &payload);
        }
        PrecedingFrame::Priority {
            stream_id,
            dependency,
            weight,
            exclusive,
        } => {
            let mut payload = Vec::new();
            let dep_field = if *exclusive {
                *dependency | 0x80000000
            } else {
                *dependency
            };
            payload.extend_from_slice(&dep_field.to_be_bytes());
            payload.push(*weight);
            conn.process_frame(FRAME_TYPE_PRIORITY, *stream_id, 0, &payload);
        }
    }
}

/// Send a follow-up frame after the HEADERS frame
fn send_follow_up_frame(conn: &mut MockInvalidMethodConnection, frame: &FollowUpFrame) {
    match frame {
        FollowUpFrame::Data {
            stream_id,
            data,
            end_stream,
        } => {
            let flags = if *end_stream { FLAG_END_STREAM } else { 0 };
            conn.process_frame(FRAME_TYPE_DATA, *stream_id, flags, data);
        }
        FollowUpFrame::Headers {
            stream_id,
            end_headers,
            end_stream,
        } => {
            let mut flags = 0;
            if *end_headers {
                flags |= FLAG_END_HEADERS;
            }
            if *end_stream {
                flags |= FLAG_END_STREAM;
            }
            conn.process_frame(FRAME_TYPE_HEADERS, *stream_id, flags, b"headers");
        }
        FollowUpFrame::RstStream {
            stream_id,
            error_code,
        } => {
            let payload = error_code.to_be_bytes().to_vec();
            conn.process_frame(FRAME_TYPE_RST_STREAM, *stream_id, 0, &payload);
        }
        FollowUpFrame::WindowUpdate {
            stream_id,
            increment,
        } => {
            let payload = increment.to_be_bytes().to_vec();
            conn.process_frame(FRAME_TYPE_WINDOW_UPDATE, *stream_id, 0, &payload);
        }
    }
}

fuzz_target!(|input: InvalidMethodInput| {
    // Limit input sizes to prevent excessive memory usage
    if input.method.len() > 1000
        || input.other_headers.len() > 100
        || input.preceding_frames.len() > 50
        || input.follow_up_frames.len() > 50
    {
        return;
    }

    // Ensure stream ID is valid (non-zero for client-initiated streams)
    let stream_id = if input.stream_id == 0 || input.stream_id > 0x7FFFFFFF {
        1
    } else {
        input.stream_id | 1 // Ensure odd (client-initiated)
    };

    let mut conn = MockInvalidMethodConnection::new();

    // Send preceding frames to set up connection state
    for frame in &input.preceding_frames {
        send_preceding_frame(&mut conn, frame);
        if conn.has_protocol_error() {
            // Stop if we hit a protocol error from setup frames
            return;
        }
    }

    // Determine if the method should be invalid
    let should_be_invalid = is_method_invalid(&input.method);

    // Create HEADERS frame payload with the method
    // In reality this would be HPACK-encoded, but we simulate with the method string
    let payload = input.method.as_bytes().to_vec();

    let mut flags = 0;
    if input.end_headers {
        flags |= FLAG_END_HEADERS;
    }
    if input.end_stream {
        flags |= FLAG_END_STREAM;
    }

    // Send the HEADERS frame with potentially invalid :method
    conn.process_frame(FRAME_TYPE_HEADERS, stream_id, flags, &payload);

    if should_be_invalid {
        // CRITICAL: Invalid :method pseudo-headers MUST be rejected
        assert!(
            conn.has_protocol_error(),
            "Invalid :method must cause protocol error. Method: {:?}, \
             END_HEADERS: {}, END_STREAM: {}, Violations: {:?}",
            input.method,
            input.end_headers,
            input.end_stream,
            conn.get_violations()
        );

        assert_eq!(
            conn.get_error_code(),
            Some(PROTOCOL_ERROR),
            "Invalid :method must result in PROTOCOL_ERROR (0x1), got {:?}. \
             Method: {:?}, Violations: {:?}",
            conn.get_error_code(),
            input.method,
            conn.get_violations()
        );

        // Verify we detected the invalid method
        assert!(
            !conn.get_invalid_methods().is_empty(),
            "Expected invalid method to be detected and recorded"
        );
    } else {
        // Valid method should not cause error
        assert!(
            !conn.has_protocol_error(),
            "Valid :method should not cause protocol error. Method: {:?}, \
             Violations: {:?}",
            input.method,
            conn.get_violations()
        );
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

    // Test specific invalid :method scenarios
    test_invalid_method_scenarios(&input);
});

/// Check if a method should be considered invalid
fn is_method_invalid(method: &str) -> bool {
    // Empty method
    if method.is_empty() {
        return true;
    }

    // Control characters
    for ch in method.chars() {
        let code = ch as u32;
        if code <= 0x1F || code == 0x7F {
            return true;
        }
    }

    // Whitespace or CRLF
    if method.contains(' ')
        || method.contains('\t')
        || method.contains('\r')
        || method.contains('\n')
    {
        return true;
    }

    // Invalid token characters
    for ch in method.chars() {
        if !is_valid_token_char(ch) {
            return true;
        }
    }

    false
}

/// Test specific invalid :method scenarios
fn test_invalid_method_scenarios(_input: &InvalidMethodInput) {
    // Scenario 1: Empty :method
    {
        let mut conn = MockInvalidMethodConnection::new();
        conn.process_frame(FRAME_TYPE_HEADERS, 1, FLAG_END_HEADERS, b"");

        assert!(
            conn.has_protocol_error(),
            "Empty :method must be rejected per RFC 7540 §8.1.2"
        );
        assert_eq!(conn.count_empty_methods(), 1);
    }

    // Scenario 2: :method with CRLF
    {
        let mut conn = MockInvalidMethodConnection::new();
        let method_with_crlf = b"GET\r\nHost: evil.com\r\n\r\n";
        conn.process_frame(FRAME_TYPE_HEADERS, 1, FLAG_END_HEADERS, method_with_crlf);

        assert!(
            conn.has_protocol_error(),
            ":method with CRLF must be rejected (request smuggling prevention)"
        );
        assert_eq!(conn.count_whitespace_methods(), 1);
    }

    // Scenario 3: :method with control characters
    {
        let control_chars = [0x00u8, 0x01, 0x08, 0x0C, 0x1F, 0x7F];
        for &control_char in &control_chars {
            let mut conn = MockInvalidMethodConnection::new();
            let mut method_with_control = b"GET".to_vec();
            method_with_control.push(control_char);

            conn.process_frame(
                FRAME_TYPE_HEADERS,
                1,
                FLAG_END_HEADERS,
                &method_with_control,
            );

            assert!(
                conn.has_protocol_error(),
                ":method with control character 0x{:02X} must be rejected",
                control_char
            );
        }
    }

    // Scenario 4: :method with spaces
    {
        let mut conn = MockInvalidMethodConnection::new();
        conn.process_frame(FRAME_TYPE_HEADERS, 1, FLAG_END_HEADERS, b"GET POST");

        assert!(
            conn.has_protocol_error(),
            ":method with space must be rejected"
        );
        assert_eq!(conn.count_whitespace_methods(), 1);
    }

    // Scenario 5: :method with tabs
    {
        let mut conn = MockInvalidMethodConnection::new();
        conn.process_frame(FRAME_TYPE_HEADERS, 1, FLAG_END_HEADERS, b"GET\tPOST");

        assert!(
            conn.has_protocol_error(),
            ":method with tab must be rejected"
        );
        assert_eq!(conn.count_whitespace_methods(), 1);
    }

    // Scenario 6: Valid methods should be accepted
    let valid_methods = [
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT",
    ];
    for method in &valid_methods {
        let mut conn = MockInvalidMethodConnection::new();
        conn.process_frame(FRAME_TYPE_HEADERS, 1, FLAG_END_HEADERS, method.as_bytes());

        assert!(
            !conn.has_protocol_error(),
            "Valid method '{}' should be accepted",
            method
        );
    }

    // Scenario 7: Custom but valid methods
    let custom_valid_methods = ["PROPFIND", "PROPPATCH", "MKCOL", "LOCK", "UNLOCK"];
    for method in &custom_valid_methods {
        let mut conn = MockInvalidMethodConnection::new();
        conn.process_frame(FRAME_TYPE_HEADERS, 1, FLAG_END_HEADERS, method.as_bytes());

        assert!(
            !conn.has_protocol_error(),
            "Custom valid method '{}' should be accepted",
            method
        );
    }

    // Scenario 8: Invalid characters in method
    let invalid_chars = [
        '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', '{', '}',
    ];
    for &invalid_char in &invalid_chars {
        let mut conn = MockInvalidMethodConnection::new();
        let mut method_with_invalid = b"GET".to_vec();
        method_with_invalid.push(invalid_char as u8);

        conn.process_frame(
            FRAME_TYPE_HEADERS,
            1,
            FLAG_END_HEADERS,
            &method_with_invalid,
        );

        assert!(
            conn.has_protocol_error(),
            ":method with invalid character '{}' must be rejected",
            invalid_char
        );
    }

    // Scenario 9: Case sensitivity (methods are case-sensitive)
    {
        let mut conn = MockInvalidMethodConnection::new();
        conn.process_frame(FRAME_TYPE_HEADERS, 1, FLAG_END_HEADERS, b"get"); // lowercase

        // Whether this is accepted depends on implementation
        // HTTP methods are case-sensitive, but "get" is technically valid as a token
        // The key is that our parser should be consistent
    }

    // Scenario 10: Very long method (potential buffer overflow)
    {
        let mut conn = MockInvalidMethodConnection::new();
        let long_method = "A".repeat(1000);
        conn.process_frame(
            FRAME_TYPE_HEADERS,
            1,
            FLAG_END_HEADERS,
            long_method.as_bytes(),
        );

        // Should not crash, regardless of whether it's accepted or rejected
        // The test is that we handle it gracefully
    }

    // Scenario 11: Method with newline only (not CRLF)
    {
        let mut conn = MockInvalidMethodConnection::new();
        conn.process_frame(FRAME_TYPE_HEADERS, 1, FLAG_END_HEADERS, b"GET\nPOST");

        assert!(
            conn.has_protocol_error(),
            ":method with newline must be rejected"
        );
        assert_eq!(conn.count_whitespace_methods(), 1);
    }

    // Scenario 12: Method with carriage return only
    {
        let mut conn = MockInvalidMethodConnection::new();
        conn.process_frame(FRAME_TYPE_HEADERS, 1, FLAG_END_HEADERS, b"GET\rPOST");

        assert!(
            conn.has_protocol_error(),
            ":method with carriage return must be rejected"
        );
        assert_eq!(conn.count_whitespace_methods(), 1);
    }
}
