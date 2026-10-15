#![no_main]

//! Fuzz target for HTTP/2 HEADERS frame with trailers validation.
//!
//! This target tests that HTTP/2 trailers are properly validated per RFC 9113:
//! - Trailers MUST only be sent after END_STREAM data
//! - Trailers MUST NOT contain pseudo-headers (§8.1)
//! - Trailers MUST NOT contain forbidden headers per RFC 9110 §6.5.1
//! - Stream must be in correct state to receive trailers
//!
//! Expected behavior:
//! - Trailers before END_STREAM: PROTOCOL_ERROR
//! - Trailers with pseudo-headers: PROTOCOL_ERROR
//! - Trailers with forbidden headers: PROTOCOL_ERROR
//! - Valid trailers after END_STREAM: accepted

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// HTTP/2 error codes (subset)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorCode {
    NoError = 0x0,
    ProtocolError = 0x1,
    InternalError = 0x2,
    FlowControlError = 0x3,
    SettingsTimeout = 0x4,
    StreamClosed = 0x5,
    FrameSizeError = 0x6,
    RefusedStream = 0x7,
    Cancel = 0x8,
    CompressionError = 0x9,
    ConnectError = 0xa,
    EnhanceYourCalm = 0xb,
    InadequateSecurity = 0xc,
    Http11Required = 0xd,
}

/// Stream state for HTTP/2 streams
#[derive(Debug, Clone, Copy, PartialEq, Eq, Arbitrary)]
enum StreamState {
    Idle,
    ReservedLocal,
    ReservedRemote,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

impl StreamState {
    fn is_closed(self) -> bool {
        self == StreamState::Closed
    }

    fn can_receive_headers(self) -> bool {
        matches!(self, StreamState::Open | StreamState::HalfClosedLocal)
    }
}

/// HTTP/2 header with name and value
#[derive(Debug, Clone, Arbitrary)]
struct Header {
    name: String,
    value: String,
}

impl Header {
    fn is_pseudo_header(&self) -> bool {
        self.name.starts_with(':')
    }

    fn is_forbidden_trailer(&self) -> bool {
        // List based on RFC 9110 §6.5.1 and RFC 9113 §8.1
        const FORBIDDEN: &[&str] = &[
            // Pseudo-headers (always forbidden in trailers)
            ":status",
            ":method",
            ":path",
            ":scheme",
            ":authority",
            // Message framing
            "content-length",
            "transfer-encoding",
            "trailer",
            // Connection-specific
            "connection",
            "keep-alive",
            "proxy-connection",
            "upgrade",
            // Request modifiers
            "authorization",
            "proxy-authorization",
            "cache-control",
            "expect",
            "host",
            "max-forwards",
            "pragma",
            "range",
            "te",
            // Response control
            "age",
            "expires",
            "date",
            "etag",
            "last-modified",
            "location",
            "retry-after",
            "server",
            "vary",
            "www-authenticate",
            "proxy-authenticate",
            // Content metadata
            "content-encoding",
            "content-range",
            "content-type",
            // Cookies and state
            "cookie",
            "set-cookie",
        ];

        let name_lower = self.name.to_lowercase();
        FORBIDDEN.contains(&name_lower.as_str())
    }

    fn generate_valid_trailer() -> Self {
        Self {
            name: "X-Trailer-Custom".to_string(),
            value: "valid-value".to_string(),
        }
    }

    fn generate_pseudo_header(pseudo_type: PseudoHeaderType) -> Self {
        match pseudo_type {
            PseudoHeaderType::Status => Self {
                name: ":status".to_string(),
                value: "200".to_string(),
            },
            PseudoHeaderType::Method => Self {
                name: ":method".to_string(),
                value: "GET".to_string(),
            },
            PseudoHeaderType::Path => Self {
                name: ":path".to_string(),
                value: "/".to_string(),
            },
            PseudoHeaderType::Scheme => Self {
                name: ":scheme".to_string(),
                value: "https".to_string(),
            },
            PseudoHeaderType::Authority => Self {
                name: ":authority".to_string(),
                value: "example.com".to_string(),
            },
        }
    }

    fn generate_forbidden_header(forbidden_type: ForbiddenHeaderType) -> Self {
        match forbidden_type {
            ForbiddenHeaderType::ContentLength => Self {
                name: "Content-Length".to_string(),
                value: "123".to_string(),
            },
            ForbiddenHeaderType::TransferEncoding => Self {
                name: "Transfer-Encoding".to_string(),
                value: "chunked".to_string(),
            },
            ForbiddenHeaderType::Authorization => Self {
                name: "Authorization".to_string(),
                value: "Bearer token".to_string(),
            },
            ForbiddenHeaderType::ContentType => Self {
                name: "Content-Type".to_string(),
                value: "text/plain".to_string(),
            },
            ForbiddenHeaderType::Host => Self {
                name: "Host".to_string(),
                value: "example.com".to_string(),
            },
            ForbiddenHeaderType::CacheControl => Self {
                name: "Cache-Control".to_string(),
                value: "no-cache".to_string(),
            },
        }
    }
}

/// Types of pseudo-headers to test
#[derive(Debug, Clone, Copy, Arbitrary)]
enum PseudoHeaderType {
    Status,
    Method,
    Path,
    Scheme,
    Authority,
}

/// Types of forbidden headers to test
#[derive(Debug, Clone, Copy, Arbitrary)]
enum ForbiddenHeaderType {
    ContentLength,
    TransferEncoding,
    Authorization,
    ContentType,
    Host,
    CacheControl,
}

/// HEADERS frame for trailers
#[derive(Debug, Clone, Arbitrary)]
struct TrailersFrame {
    /// Stream identifier
    stream_id: u32,
    /// Headers in the trailers
    headers: Vec<Header>,
    /// Whether END_HEADERS flag is set
    end_headers: bool,
    /// Whether END_STREAM flag is set (required for trailers)
    end_stream: bool,
    /// Include pseudo-headers (should be rejected)
    include_pseudo_headers: bool,
    /// Pseudo-header to include (if enabled)
    pseudo_header_type: Option<PseudoHeaderType>,
    /// Include forbidden headers (should be rejected)
    include_forbidden_headers: bool,
    /// Forbidden header to include (if enabled)
    forbidden_header_type: Option<ForbiddenHeaderType>,
}

impl TrailersFrame {
    fn generate_headers(&self) -> Vec<Header> {
        let mut headers = self.headers.clone();

        // Add pseudo-headers if requested
        if self.include_pseudo_headers {
            if let Some(pseudo_type) = self.pseudo_header_type {
                headers.insert(0, Header::generate_pseudo_header(pseudo_type));
            }
        }

        // Add forbidden headers if requested
        if self.include_forbidden_headers {
            if let Some(forbidden_type) = self.forbidden_header_type {
                headers.push(Header::generate_forbidden_header(forbidden_type));
            }
        }

        // Ensure we have at least one valid header for testing
        if headers.is_empty() {
            headers.push(Header::generate_valid_trailer());
        }

        headers
    }

    fn should_be_rejected(&self) -> bool {
        // Check various rejection conditions

        // Stream ID 0 is invalid for HEADERS
        if self.stream_id == 0 {
            return true;
        }

        // Trailers without END_STREAM should be rejected
        if !self.end_stream {
            return true;
        }

        // Check for pseudo-headers in trailers
        let generated_headers = self.generate_headers();
        if generated_headers.iter().any(|h| h.is_pseudo_header()) {
            return true;
        }

        // Check for forbidden headers in trailers
        if generated_headers.iter().any(|h| h.is_forbidden_trailer()) {
            return true;
        }

        false
    }
}

/// Mock HTTP/2 stream for testing trailers
struct MockStream {
    id: u32,
    state: StreamState,
    initial_headers_received: bool,
    data_ended: bool,
    trailers_received: bool,
}

impl MockStream {
    fn new(id: u32, state: StreamState) -> Self {
        Self {
            id,
            state,
            initial_headers_received: false,
            data_ended: false,
            trailers_received: false,
        }
    }

    fn receive_initial_headers(&mut self, end_stream: bool) -> Result<(), ErrorCode> {
        if !self.state.can_receive_headers() {
            return Err(ErrorCode::StreamClosed);
        }

        self.initial_headers_received = true;

        if end_stream {
            self.data_ended = true;
            self.state = StreamState::HalfClosedRemote;
        }

        Ok(())
    }

    fn receive_data(&mut self, end_stream: bool) -> Result<(), ErrorCode> {
        if !self.state.can_receive_headers() {
            return Err(ErrorCode::StreamClosed);
        }

        if !self.initial_headers_received {
            return Err(ErrorCode::ProtocolError);
        }

        if end_stream {
            self.data_ended = true;
            self.state = StreamState::HalfClosedRemote;
        }

        Ok(())
    }

    fn receive_trailers(&mut self, headers: &[Header], end_stream: bool) -> Result<(), ErrorCode> {
        if !self.state.can_receive_headers() {
            return Err(ErrorCode::StreamClosed);
        }

        // Trailers can only come after initial headers
        if !self.initial_headers_received {
            return Err(ErrorCode::ProtocolError);
        }

        // Trailers can only come after data has ended
        if !self.data_ended {
            return Err(ErrorCode::ProtocolError);
        }

        // Trailers must have END_STREAM flag
        if !end_stream {
            return Err(ErrorCode::ProtocolError);
        }

        // Already received trailers
        if self.trailers_received {
            return Err(ErrorCode::ProtocolError);
        }

        // Validate headers - no pseudo-headers allowed
        for header in headers {
            if header.is_pseudo_header() {
                return Err(ErrorCode::ProtocolError);
            }

            if header.is_forbidden_trailer() {
                return Err(ErrorCode::ProtocolError);
            }
        }

        self.trailers_received = true;
        self.state = StreamState::Closed;
        Ok(())
    }
}

/// Mock HTTP/2 connection for testing trailers
struct MockConnection {
    streams: HashMap<u32, MockStream>,
    is_client: bool,
}

impl MockConnection {
    fn new(is_client: bool) -> Self {
        Self {
            streams: HashMap::new(),
            is_client,
        }
    }

    fn create_stream(&mut self, stream_id: u32) -> Result<(), ErrorCode> {
        if stream_id == 0 {
            return Err(ErrorCode::ProtocolError);
        }

        let state = if self.is_client {
            if stream_id % 2 == 0 {
                StreamState::ReservedLocal
            } else {
                StreamState::Open
            }
        } else {
            if stream_id % 2 == 1 {
                StreamState::ReservedLocal
            } else {
                StreamState::Open
            }
        };

        self.streams
            .insert(stream_id, MockStream::new(stream_id, state));
        Ok(())
    }

    fn process_initial_headers(
        &mut self,
        stream_id: u32,
        end_stream: bool,
    ) -> Result<(), ErrorCode> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(ErrorCode::InternalError)?;
        stream.receive_initial_headers(end_stream)
    }

    fn process_data(&mut self, stream_id: u32, end_stream: bool) -> Result<(), ErrorCode> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(ErrorCode::InternalError)?;
        stream.receive_data(end_stream)
    }

    fn process_trailers(&mut self, frame: &TrailersFrame) -> Result<(), ErrorCode> {
        let stream = self
            .streams
            .get_mut(&frame.stream_id)
            .ok_or(ErrorCode::InternalError)?;
        let headers = frame.generate_headers();
        stream.receive_trailers(&headers, frame.end_stream)
    }
}

/// Test scenario for trailers validation
#[derive(Debug, Clone, Arbitrary)]
struct TrailersScenario {
    /// Trailers frame to test
    trailers_frame: TrailersFrame,
    /// Whether to send initial headers first
    send_initial_headers: bool,
    /// Whether initial headers should end stream
    initial_headers_end_stream: bool,
    /// Whether to send data frames first
    send_data_frames: bool,
    /// Whether data frames should end stream
    data_frames_end_stream: bool,
    /// Stream state setup
    initial_stream_state: StreamState,
}

fuzz_target!(|scenario: TrailersScenario| {
    // Test both client and server perspectives
    for &is_client in &[true, false] {
        let mut connection = MockConnection::new(is_client);

        // Ensure non-zero stream ID
        let stream_id = if scenario.trailers_frame.stream_id == 0 {
            1
        } else {
            scenario.trailers_frame.stream_id
        };

        // Create stream
        if connection.create_stream(stream_id).is_err() {
            continue; // Skip invalid stream creation
        }

        // Send initial headers if requested
        if scenario.send_initial_headers {
            let result =
                connection.process_initial_headers(stream_id, scenario.initial_headers_end_stream);
            if result.is_err() {
                continue; // Skip if initial headers fail
            }
        }

        // Send data frames if requested (and not already ended by headers)
        if scenario.send_data_frames && !scenario.initial_headers_end_stream {
            let result = connection.process_data(stream_id, scenario.data_frames_end_stream);
            if result.is_err() {
                continue; // Skip if data frames fail
            }
        }

        // Now test the trailers frame
        let trailers_frame = TrailersFrame {
            stream_id,
            headers: scenario.trailers_frame.headers.clone(),
            end_headers: scenario.trailers_frame.end_headers,
            end_stream: scenario.trailers_frame.end_stream,
            include_pseudo_headers: scenario.trailers_frame.include_pseudo_headers,
            pseudo_header_type: scenario.trailers_frame.pseudo_header_type,
            include_forbidden_headers: scenario.trailers_frame.include_forbidden_headers,
            forbidden_header_type: scenario.trailers_frame.forbidden_header_type,
        };

        let result = connection.process_trailers(&trailers_frame);

        // Validate the result
        match result {
            Ok(()) => {
                // Trailers were accepted - validate this was expected
                assert!(
                    !trailers_frame.should_be_rejected(),
                    "Trailers should have been rejected but were accepted"
                );

                // Additional checks for valid trailers
                assert!(
                    scenario.send_initial_headers,
                    "Valid trailers require initial headers"
                );
                assert!(
                    scenario.initial_headers_end_stream || scenario.data_frames_end_stream,
                    "Valid trailers require END_STREAM data"
                );
                assert!(
                    trailers_frame.end_stream,
                    "Valid trailers must have END_STREAM"
                );
            }
            Err(error_code) => {
                // Trailers were rejected - validate the error
                match error_code {
                    ErrorCode::ProtocolError => {
                        // This is the expected error for most trailer violations
                        assert!(
                            trailers_frame.should_be_rejected()
                                || !scenario.send_initial_headers
                                || (!scenario.initial_headers_end_stream
                                    && !scenario.data_frames_end_stream)
                                || !trailers_frame.end_stream,
                            "PROTOCOL_ERROR but trailers seem valid"
                        );
                    }
                    ErrorCode::InternalError => {
                        // Stream not found or internal state issue
                        // This can happen in edge cases
                    }
                    ErrorCode::StreamClosed => {
                        // Stream in wrong state for trailers
                        assert!(
                            scenario.initial_stream_state.is_closed()
                                || !scenario.initial_stream_state.can_receive_headers(),
                            "STREAM_CLOSED but stream state seems valid"
                        );
                    }
                    _ => {
                        panic!("Unexpected error code for trailers: {:?}", error_code);
                    }
                }
            }
        }
    }

    // Test specific trailer validation scenarios
    test_trailer_boundary_conditions();
});

/// Test specific boundary conditions for trailer validation
fn test_trailer_boundary_conditions() {
    let mut connection = MockConnection::new(false); // Server perspective

    // Test 1: Valid trailers after proper setup
    connection.create_stream(1).unwrap();
    connection.process_initial_headers(1, false).unwrap();
    connection.process_data(1, true).unwrap(); // END_STREAM data

    let valid_trailers = TrailersFrame {
        stream_id: 1,
        headers: vec![Header::generate_valid_trailer()],
        end_headers: true,
        end_stream: true,
        include_pseudo_headers: false,
        pseudo_header_type: None,
        include_forbidden_headers: false,
        forbidden_header_type: None,
    };

    let result = connection.process_trailers(&valid_trailers);
    assert!(result.is_ok(), "Valid trailers should be accepted");

    // Test 2: Trailers with pseudo-headers (should fail)
    let mut connection2 = MockConnection::new(false);
    connection2.create_stream(3).unwrap();
    connection2.process_initial_headers(3, false).unwrap();
    connection2.process_data(3, true).unwrap();

    let pseudo_trailers = TrailersFrame {
        stream_id: 3,
        headers: vec![Header::generate_valid_trailer()],
        end_headers: true,
        end_stream: true,
        include_pseudo_headers: true,
        pseudo_header_type: Some(PseudoHeaderType::Status),
        include_forbidden_headers: false,
        forbidden_header_type: None,
    };

    let result = connection2.process_trailers(&pseudo_trailers);
    assert_eq!(
        result,
        Err(ErrorCode::ProtocolError),
        "Pseudo-headers in trailers should fail"
    );

    // Test 3: Trailers with forbidden headers (should fail)
    let mut connection3 = MockConnection::new(false);
    connection3.create_stream(5).unwrap();
    connection3.process_initial_headers(5, false).unwrap();
    connection3.process_data(5, true).unwrap();

    let forbidden_trailers = TrailersFrame {
        stream_id: 5,
        headers: vec![Header::generate_valid_trailer()],
        end_headers: true,
        end_stream: true,
        include_pseudo_headers: false,
        pseudo_header_type: None,
        include_forbidden_headers: true,
        forbidden_header_type: Some(ForbiddenHeaderType::ContentLength),
    };

    let result = connection3.process_trailers(&forbidden_trailers);
    assert_eq!(
        result,
        Err(ErrorCode::ProtocolError),
        "Forbidden headers in trailers should fail"
    );

    // Test 4: Trailers before END_STREAM (should fail)
    let mut connection4 = MockConnection::new(false);
    connection4.create_stream(7).unwrap();
    connection4.process_initial_headers(7, false).unwrap();
    // Don't send END_STREAM data

    let premature_trailers = TrailersFrame {
        stream_id: 7,
        headers: vec![Header::generate_valid_trailer()],
        end_headers: true,
        end_stream: true,
        include_pseudo_headers: false,
        pseudo_header_type: None,
        include_forbidden_headers: false,
        forbidden_header_type: None,
    };

    let result = connection4.process_trailers(&premature_trailers);
    assert_eq!(
        result,
        Err(ErrorCode::ProtocolError),
        "Trailers before END_STREAM should fail"
    );
}
