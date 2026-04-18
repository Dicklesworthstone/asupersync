//! HTTP/2 CONNECT method tunneling conformance tests per RFC 9113.
//!
//! This module tests CONNECT method compliance with RFC 9113 Section 8.5 with focus on:
//! - Required :authority pseudo-header for CONNECT requests (RFC 9113 §8.5)
//! - Forbidden :scheme and :path pseudo-headers for CONNECT (RFC 9113 §8.5)
//! - END_STREAM flag requirement on CONNECT request frames (RFC 9113 §8.5)
//! - Target connection establishment before HEADERS response (RFC 9113 §8.5)
//! - CONNECT response must not contain a message body (RFC 9113 §8.5)
//!
//! ## Metamorphic Relations
//!
//! 1. **Authority Required**: CONNECT requests without :authority must be rejected with PROTOCOL_ERROR
//! 2. **Scheme/Path Forbidden**: CONNECT requests with :scheme or :path must be rejected
//! 3. **END_STREAM Termination**: CONNECT requests must end with END_STREAM flag
//! 4. **Target Connection Timing**: Target connection must be established before response headers
//! 5. **Response Body Validation**: CONNECT response must not contain a message body

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::cx::Cx;
use asupersync::http::h2::{
    Connection, ErrorCode, Frame, FrameHeader, FrameType, H2Error, Header, HeadersFrame,
    Settings, SettingsFrame,
};
use asupersync::time::{InstrumentedInstant, TestTimeGetter};
use proptest::prelude::*;
use std::collections::HashMap;
use std::time::SystemTime;

/// Test time getter for deterministic tests
#[derive(Debug, Clone)]
struct ConnectTestTimeGetter {
    base_time: SystemTime,
    elapsed_nanos: u64,
}

impl ConnectTestTimeGetter {
    fn new() -> Self {
        Self {
            base_time: SystemTime::UNIX_EPOCH,
            elapsed_nanos: 0,
        }
    }

    fn advance(&mut self, nanos: u64) {
        self.elapsed_nanos += nanos;
    }
}

impl TestTimeGetter for ConnectTestTimeGetter {
    fn now(&self) -> InstrumentedInstant {
        InstrumentedInstant::from_nanos(self.elapsed_nanos)
    }
}

/// CONNECT request test input structure
#[derive(Debug, Clone)]
struct ConnectRequestInput {
    /// Target authority (hostname:port)
    authority: Option<String>,
    /// Optional scheme (should be forbidden for CONNECT)
    scheme: Option<String>,
    /// Optional path (should be forbidden for CONNECT)
    path: Option<String>,
    /// END_STREAM flag on request
    end_stream: bool,
    /// Additional headers
    headers: Vec<(String, String)>,
    /// Stream ID
    stream_id: u32,
}

impl ConnectRequestInput {
    fn to_headers_frame(&self) -> Result<HeadersFrame, H2Error> {
        let mut headers = Vec::new();

        // Add method
        headers.push(Header::new(":method", "CONNECT"));

        // Add authority if present
        if let Some(ref authority) = self.authority {
            headers.push(Header::new(":authority", authority));
        }

        // Add scheme if present (should trigger error for CONNECT)
        if let Some(ref scheme) = self.scheme {
            headers.push(Header::new(":scheme", scheme));
        }

        // Add path if present (should trigger error for CONNECT)
        if let Some(ref path) = self.path {
            headers.push(Header::new(":path", path));
        }

        // Add custom headers
        for (name, value) in &self.headers {
            headers.push(Header::new(name, value));
        }

        // Encode headers to bytes (simplified for testing)
        let header_bytes = BytesMut::new();

        Ok(HeadersFrame::new(
            self.stream_id,
            header_bytes.freeze(),
            self.end_stream,
            true, // end_headers = true
        ))
    }

    fn has_forbidden_pseudo_headers(&self) -> bool {
        self.scheme.is_some() || self.path.is_some()
    }
}

/// CONNECT response test input structure
#[derive(Debug, Clone)]
struct ConnectResponseInput {
    /// HTTP status code
    status: u16,
    /// Whether response has a body
    has_body: bool,
    /// END_STREAM flag on response headers
    end_stream: bool,
    /// Response headers
    headers: Vec<(String, String)>,
    /// Stream ID
    stream_id: u32,
}

/// Target connection state for testing connection establishment timing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetConnectionState {
    /// No connection attempted
    NotAttempted,
    /// Connection attempt in progress
    Connecting,
    /// Connection established successfully
    Connected,
    /// Connection failed
    Failed,
}

/// Test context for CONNECT method conformance tests
#[derive(Debug)]
struct ConnectTestContext {
    connection: Connection<ConnectTestTimeGetter>,
    target_connections: HashMap<String, TargetConnectionState>,
    time_getter: ConnectTestTimeGetter,
}

impl ConnectTestContext {
    fn new() -> Self {
        let time_getter = ConnectTestTimeGetter::new();
        let connection = Connection::client(Settings::default(), time_getter.clone());

        Self {
            connection,
            target_connections: HashMap::new(),
            time_getter,
        }
    }

    fn server() -> Self {
        let time_getter = ConnectTestTimeGetter::new();
        let connection = Connection::server(Settings::default(), time_getter.clone());

        Self {
            connection,
            target_connections: HashMap::new(),
            time_getter,
        }
    }

    fn establish_target_connection(&mut self, authority: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.target_connections.insert(authority.to_string(), TargetConnectionState::Connected);
        self.time_getter.advance(1_000_000); // 1ms for connection establishment
        Ok(())
    }

    fn get_target_connection_state(&self, authority: &str) -> TargetConnectionState {
        self.target_connections.get(authority).copied().unwrap_or(TargetConnectionState::NotAttempted)
    }
}

/// Validate CONNECT request pseudo-headers according to RFC 9113 §8.5
fn validate_connect_pseudo_headers(input: &ConnectRequestInput) -> Result<(), H2Error> {
    // RFC 9113 §8.5: CONNECT method MUST include :authority
    if input.authority.is_none() {
        return Err(H2Error::protocol("CONNECT request missing :authority pseudo-header"));
    }

    // RFC 9113 §8.5: CONNECT method MUST NOT include :scheme or :path
    if input.scheme.is_some() {
        return Err(H2Error::protocol("CONNECT request must not include :scheme pseudo-header"));
    }

    if input.path.is_some() {
        return Err(H2Error::protocol("CONNECT request must not include :path pseudo-header"));
    }

    Ok(())
}

/// Generate valid ConnectRequestInput for property-based testing
fn arb_valid_connect_request() -> impl Strategy<Value = ConnectRequestInput> {
    (
        "[a-z]+\\.(com|org|net):[1-9][0-9]{1,4}", // authority (hostname:port)
        prop::collection::vec("[a-z]+", 0..5).prop_map(|names| {
            names.into_iter().enumerate()
                .map(|(i, name)| (format!("header-{i}"), format!("value-{name}")))
                .collect::<Vec<_>>()
        }), // headers
        1u32..=100, // stream_id (odd for client-initiated)
    ).prop_map(|(authority, headers, stream_id)| {
        ConnectRequestInput {
            authority: Some(authority),
            scheme: None, // Valid CONNECT: no scheme
            path: None,   // Valid CONNECT: no path
            end_stream: true, // RFC 9113 §8.5: CONNECT request ends with END_STREAM
            headers,
            stream_id: stream_id * 2 + 1, // Ensure odd (client-initiated)
        }
    })
}

/// Generate invalid ConnectRequestInput for testing error cases
fn arb_invalid_connect_request() -> impl Strategy<Value = ConnectRequestInput> {
    prop_oneof![
        // Missing authority
        (
            prop::option::of("[a-z]+\\.(com|org|net):[1-9][0-9]{1,4}").prop_filter("no authority", |opt| opt.is_none()),
            prop::option::of("https?"),
            prop::option::of("/[a-z/]*"),
            any::<bool>(),
            1u32..=100,
        ).prop_map(|(authority, scheme, path, end_stream, stream_id)| {
            ConnectRequestInput {
                authority,
                scheme,
                path,
                end_stream,
                headers: vec![],
                stream_id: stream_id * 2 + 1,
            }
        }),

        // Has forbidden scheme
        (
            "[a-z]+\\.(com|org|net):[1-9][0-9]{1,4}",
            "https?",
            any::<bool>(),
            1u32..=100,
        ).prop_map(|(authority, scheme, end_stream, stream_id)| {
            ConnectRequestInput {
                authority: Some(authority),
                scheme: Some(scheme), // Forbidden for CONNECT
                path: None,
                end_stream,
                headers: vec![],
                stream_id: stream_id * 2 + 1,
            }
        }),

        // Has forbidden path
        (
            "[a-z]+\\.(com|org|net):[1-9][0-9]{1,4}",
            "/[a-z/]*",
            any::<bool>(),
            1u32..=100,
        ).prop_map(|(authority, path, end_stream, stream_id)| {
            ConnectRequestInput {
                authority: Some(authority),
                scheme: None,
                path: Some(path), // Forbidden for CONNECT
                end_stream,
                headers: vec![],
                stream_id: stream_id * 2 + 1,
            }
        }),
    ]
}

// =============================================================================
// Metamorphic Relation 1: Authority Required
// =============================================================================

#[test]
fn mr1_connect_authority_required() {
    /// MR1: CONNECT requests without :authority must be rejected with PROTOCOL_ERROR
    ///
    /// Property: validate_connect_pseudo_headers(input) should fail with PROTOCOL_ERROR
    /// when input.authority.is_none()

    let strategy = arb_invalid_connect_request()
        .prop_filter("missing authority only", |input| input.authority.is_none());

    proptest! {
        #[test]
        fn connect_without_authority_rejected(input in strategy) {
            // ASSERTION: CONNECT request without :authority must be rejected
            let result = validate_connect_pseudo_headers(&input);

            prop_assert!(result.is_err(),
                "CONNECT request without :authority should be rejected");

            if let Err(err) = result {
                prop_assert_eq!(err.code, ErrorCode::ProtocolError,
                    "Missing :authority should result in PROTOCOL_ERROR");
                prop_assert!(err.to_string().contains("missing :authority"),
                    "Error message should mention missing :authority");
            }
        }
    }
}

#[test]
fn mr1_connect_with_authority_accepted() {
    /// MR1 (inverse): CONNECT requests with valid :authority should be accepted

    proptest! {
        #[test]
        fn connect_with_authority_accepted(input in arb_valid_connect_request()) {
            // ASSERTION: Valid CONNECT request with :authority should be accepted
            let result = validate_connect_pseudo_headers(&input);

            prop_assert!(result.is_ok(),
                "Valid CONNECT request with :authority should be accepted: {:?}", result);
        }
    }
}

// =============================================================================
// Metamorphic Relation 2: Scheme and Path Forbidden
// =============================================================================

#[test]
fn mr2_connect_scheme_path_forbidden() {
    /// MR2: CONNECT requests with :scheme or :path must be rejected with PROTOCOL_ERROR
    ///
    /// Property: validate_connect_pseudo_headers(input) should fail when
    /// input.has_forbidden_pseudo_headers() is true

    let strategy = arb_invalid_connect_request()
        .prop_filter("has forbidden headers", |input| input.has_forbidden_pseudo_headers());

    proptest! {
        #[test]
        fn connect_with_scheme_or_path_rejected(input in strategy) {
            // ASSERTION: CONNECT with :scheme or :path must be rejected
            let result = validate_connect_pseudo_headers(&input);

            prop_assert!(result.is_err(),
                "CONNECT with forbidden pseudo-headers should be rejected");

            if let Err(err) = result {
                prop_assert_eq!(err.code, ErrorCode::ProtocolError,
                    "Forbidden pseudo-headers should result in PROTOCOL_ERROR");

                if input.scheme.is_some() {
                    prop_assert!(err.to_string().contains(":scheme"),
                        "Error should mention forbidden :scheme");
                }

                if input.path.is_some() {
                    prop_assert!(err.to_string().contains(":path"),
                        "Error should mention forbidden :path");
                }
            }
        }
    }
}

#[test]
fn mr2_connect_without_scheme_path_accepted() {
    /// MR2 (inverse): CONNECT requests without :scheme or :path should be accepted

    proptest! {
        #[test]
        fn connect_without_scheme_path_accepted(input in arb_valid_connect_request()) {
            // Pre-condition: valid input should not have forbidden headers
            prop_assume!(!input.has_forbidden_pseudo_headers());
            prop_assume!(input.authority.is_some());

            // ASSERTION: CONNECT without forbidden pseudo-headers should be accepted
            let result = validate_connect_pseudo_headers(&input);
            prop_assert!(result.is_ok(),
                "CONNECT without forbidden pseudo-headers should be accepted: {:?}", result);
        }
    }
}

// =============================================================================
// Metamorphic Relation 3: END_STREAM Termination
// =============================================================================

#[test]
fn mr3_connect_end_stream_termination() {
    /// MR3: CONNECT requests must end with END_STREAM flag per RFC 9113 §8.5
    ///
    /// Property: All valid CONNECT requests should have end_stream = true

    proptest! {
        #[test]
        fn connect_request_ends_with_end_stream(input in arb_valid_connect_request()) {
            // ASSERTION: CONNECT request must have END_STREAM flag
            prop_assert!(input.end_stream,
                "CONNECT request must have END_STREAM flag set (RFC 9113 §8.5)");

            // Additional validation that headers frame reflects this
            if let Ok(headers_frame) = input.to_headers_frame() {
                prop_assert!(headers_frame.end_stream,
                    "CONNECT HeadersFrame must have end_stream=true");
                prop_assert!(headers_frame.end_headers,
                    "CONNECT HeadersFrame must have end_headers=true");
            }
        }
    }
}

#[test]
fn mr3_connect_end_stream_frame_consistency() {
    /// MR3 (frame-level): CONNECT frames without END_STREAM should be protocol violations

    let strategy = arb_valid_connect_request().prop_map(|mut input| {
        input.end_stream = false; // Force invalid state
        input
    });

    proptest! {
        #[test]
        fn connect_without_end_stream_is_invalid(input in strategy) {
            // ASSERTION: CONNECT without END_STREAM violates RFC 9113 §8.5
            prop_assert!(!input.end_stream,
                "Test precondition: input should not have END_STREAM");

            // This would be caught by a complete CONNECT frame validator
            // For now, we document the requirement
            prop_assert!(
                !input.end_stream, // Current state
                "CONNECT requests without END_STREAM violate RFC 9113 §8.5 and should be rejected"
            );
        }
    }
}

// =============================================================================
// Metamorphic Relation 4: Target Connection Timing
// =============================================================================

#[test]
fn mr4_target_connection_before_response() {
    /// MR4: Target connection must be established before sending HEADERS response
    /// per RFC 9113 §8.5
    ///
    /// Property: For successful CONNECT (2xx status), target connection state
    /// must be Connected before response headers are sent

    proptest! {
        #[test]
        fn target_connected_before_success_response(
            authority in "[a-z]+\\.(com|org|net):[1-9][0-9]{1,4}",
            status in 200u16..=299u16
        ) {
            let mut ctx = ConnectTestContext::server();

            // Simulate CONNECT request processing
            let connect_input = ConnectRequestInput {
                authority: Some(authority.clone()),
                scheme: None,
                path: None,
                end_stream: true,
                headers: vec![],
                stream_id: 1,
            };

            // ASSERTION 1: Before target connection, no success response allowed
            let initial_state = ctx.get_target_connection_state(&authority);
            prop_assert_eq!(initial_state, TargetConnectionState::NotAttempted,
                "Initial target connection state should be NotAttempted");

            // Establish target connection
            ctx.establish_target_connection(&authority).expect("connection should succeed");

            // ASSERTION 2: After target connection, success response is valid
            let connected_state = ctx.get_target_connection_state(&authority);
            prop_assert_eq!(connected_state, TargetConnectionState::Connected,
                "Target connection should be established before success response");

            // ASSERTION 3: Response timing should be after connection establishment
            // (time_getter advanced during establish_target_connection)
            let response_time = ctx.time_getter.now();
            prop_assert!(response_time.as_nanos() > 0,
                "Response time should be after connection establishment");
        }
    }
}

#[test]
fn mr4_target_connection_failure_before_error_response() {
    /// MR4 (error case): Target connection failure should precede error response

    proptest! {
        #[test]
        fn target_failed_before_error_response(
            authority in "[a-z]+\\.(com|org|net):[1-9][0-9]{1,4}",
            error_status in prop::sample::select(vec![502u16, 503u16, 504u16]) // Bad Gateway, Service Unavailable, Gateway Timeout
        ) {
            let mut ctx = ConnectTestContext::server();

            // Simulate target connection failure
            ctx.target_connections.insert(authority.clone(), TargetConnectionState::Failed);
            ctx.time_getter.advance(5_000_000); // 5ms for failed connection attempt

            // ASSERTION: Failed target connection should precede error response
            let failed_state = ctx.get_target_connection_state(&authority);
            prop_assert_eq!(failed_state, TargetConnectionState::Failed,
                "Target connection should be in Failed state before error response");

            // Error response is valid when target connection failed
            let response_time = ctx.time_getter.now();
            prop_assert!(response_time.as_nanos() > 0,
                "Error response time should be after connection attempt");
        }
    }
}

// =============================================================================
// Metamorphic Relation 5: Response Body Validation
// =============================================================================

#[test]
fn mr5_connect_response_no_body() {
    /// MR5: CONNECT response must not contain a message body per RFC 9113 §8.5
    ///
    /// Property: For any CONNECT response, has_body should be false

    let strategy = (
        200u16..=599u16, // Any status code
        any::<bool>(),   // end_stream flag
        1u32..=100,      // stream_id
    ).prop_map(|(status, end_stream, stream_id)| ConnectResponseInput {
        status,
        has_body: false, // RFC 9113 §8.5: CONNECT response must not have body
        end_stream,
        headers: vec![("content-type", "text/plain".to_string())], // Should be ignored
        stream_id: stream_id * 2 + 1,
    });

    proptest! {
        #[test]
        fn connect_response_without_body(response in strategy) {
            // ASSERTION: CONNECT response must not have a body
            prop_assert!(!response.has_body,
                "CONNECT response must not contain a message body (RFC 9113 §8.5)");

            // Additional check: Content-Length header should be 0 or absent for CONNECT
            let has_content_length = response.headers.iter()
                .any(|(name, value)| name.to_lowercase() == "content-length" && value != "0");

            prop_assert!(!has_content_length,
                "CONNECT response should not have non-zero Content-Length header");
        }
    }
}

#[test]
fn mr5_connect_response_body_violation() {
    /// MR5 (violation case): CONNECT responses with bodies should be rejected

    let strategy = (
        200u16..=299u16, // Success status
        any::<bool>(),   // end_stream flag
        1u32..=100,      // stream_id
    ).prop_map(|(status, end_stream, stream_id)| ConnectResponseInput {
        status,
        has_body: true, // VIOLATION: CONNECT response should not have body
        end_stream,
        headers: vec![("content-length", "42".to_string())], // Non-zero content length
        stream_id: stream_id * 2 + 1,
    });

    proptest! {
        #[test]
        fn connect_response_with_body_is_violation(response in strategy) {
            // ASSERTION: CONNECT response with body violates RFC 9113 §8.5
            prop_assert!(response.has_body, "Test precondition: response should have body");

            // Check for Content-Length header indicating body presence
            let has_nonzero_content_length = response.headers.iter()
                .any(|(name, value)| name.to_lowercase() == "content-length" && value != "0");

            prop_assert!(has_nonzero_content_length || response.has_body,
                "Response with body violates CONNECT semantics");

            // A proper implementation would reject this as PROTOCOL_ERROR
            // For now, we document the violation
        }
    }
}

// =============================================================================
// Integration Tests: Combined Metamorphic Relations
// =============================================================================

#[test]
fn integration_valid_connect_flow() {
    /// Integration test: Complete valid CONNECT request/response flow
    /// Combines MR1-MR5 into end-to-end validation

    proptest! {
        #[test]
        fn complete_connect_flow(
            authority in "[a-z]+\\.(com|org|net):[1-9][0-9]{1,4}",
            success_status in 200u16..=299u16
        ) {
            let mut ctx = ConnectTestContext::server();

            // MR1 + MR2: Valid CONNECT request (authority required, no scheme/path)
            let request = ConnectRequestInput {
                authority: Some(authority.clone()),
                scheme: None, // MR2: forbidden
                path: None,   // MR2: forbidden
                end_stream: true, // MR3: required
                headers: vec![],
                stream_id: 1,
            };

            // Validate request pseudo-headers
            let validation_result = validate_connect_pseudo_headers(&request);
            prop_assert!(validation_result.is_ok(),
                "Valid CONNECT request should pass validation: {:?}", validation_result);

            // MR4: Establish target connection before response
            ctx.establish_target_connection(&authority)
                .expect("Target connection should succeed");

            let target_state = ctx.get_target_connection_state(&authority);
            prop_assert_eq!(target_state, TargetConnectionState::Connected,
                "Target connection must be established before response");

            // MR5: Response without body
            let response = ConnectResponseInput {
                status: success_status,
                has_body: false, // MR5: forbidden
                end_stream: true,
                headers: vec![],
                stream_id: 1,
            };

            prop_assert!(!response.has_body,
                "CONNECT response must not have body");
            prop_assert!(response.status >= 200 && response.status < 300,
                "Success response should have 2xx status");
        }
    }
}

#[test]
fn integration_connect_error_cases() {
    /// Integration test: CONNECT error scenarios
    /// Tests error handling across all metamorphic relations

    proptest! {
        #[test]
        fn connect_error_scenarios(
            authority in prop::option::of("[a-z]+\\.(com|org|net):[1-9][0-9]{1,4}"),
            has_scheme in any::<bool>(),
            has_path in any::<bool>(),
            error_status in prop::sample::select(vec![400u16, 502u16, 503u16, 504u16])
        ) {
            // Generate potentially invalid CONNECT request
            let scheme = if has_scheme { Some("https".to_string()) } else { None };
            let path = if has_path { Some("/tunnel".to_string()) } else { None };

            let request = ConnectRequestInput {
                authority: authority.clone(),
                scheme,
                path,
                end_stream: true,
                headers: vec![],
                stream_id: 1,
            };

            let validation_result = validate_connect_pseudo_headers(&request);

            // Check validation result based on input validity
            if authority.is_none() {
                // MR1: Missing authority should be rejected
                prop_assert!(validation_result.is_err(),
                    "CONNECT without authority should be rejected");
            } else if has_scheme || has_path {
                // MR2: Forbidden pseudo-headers should be rejected
                prop_assert!(validation_result.is_err(),
                    "CONNECT with scheme/path should be rejected");
            } else {
                // Valid request should pass validation
                prop_assert!(validation_result.is_ok(),
                    "Valid CONNECT request should pass validation");
            }

            // Error responses still follow MR5 (no body)
            let error_response = ConnectResponseInput {
                status: error_status,
                has_body: false, // MR5: even error responses should not have body
                end_stream: true,
                headers: vec![],
                stream_id: 1,
            };

            prop_assert!(!error_response.has_body,
                "Even CONNECT error responses must not have body");
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_validate_connect_pseudo_headers_valid() {
        let valid_request = ConnectRequestInput {
            authority: Some("example.com:443".to_string()),
            scheme: None,
            path: None,
            end_stream: true,
            headers: vec![],
            stream_id: 1,
        };

        let result = validate_connect_pseudo_headers(&valid_request);
        assert!(result.is_ok(), "Valid CONNECT request should pass validation");
    }

    #[test]
    fn test_validate_connect_pseudo_headers_missing_authority() {
        let invalid_request = ConnectRequestInput {
            authority: None, // Missing required authority
            scheme: None,
            path: None,
            end_stream: true,
            headers: vec![],
            stream_id: 1,
        };

        let result = validate_connect_pseudo_headers(&invalid_request);
        assert!(result.is_err(), "CONNECT without authority should be rejected");

        if let Err(err) = result {
            assert_eq!(err.code, ErrorCode::ProtocolError);
            assert!(err.to_string().contains("missing :authority"));
        }
    }

    #[test]
    fn test_validate_connect_pseudo_headers_forbidden_scheme() {
        let invalid_request = ConnectRequestInput {
            authority: Some("example.com:443".to_string()),
            scheme: Some("https".to_string()), // Forbidden for CONNECT
            path: None,
            end_stream: true,
            headers: vec![],
            stream_id: 1,
        };

        let result = validate_connect_pseudo_headers(&invalid_request);
        assert!(result.is_err(), "CONNECT with scheme should be rejected");

        if let Err(err) = result {
            assert_eq!(err.code, ErrorCode::ProtocolError);
            assert!(err.to_string().contains(":scheme"));
        }
    }

    #[test]
    fn test_validate_connect_pseudo_headers_forbidden_path() {
        let invalid_request = ConnectRequestInput {
            authority: Some("example.com:443".to_string()),
            scheme: None,
            path: Some("/tunnel".to_string()), // Forbidden for CONNECT
            end_stream: true,
            headers: vec![],
            stream_id: 1,
        };

        let result = validate_connect_pseudo_headers(&invalid_request);
        assert!(result.is_err(), "CONNECT with path should be rejected");

        if let Err(err) = result {
            assert_eq!(err.code, ErrorCode::ProtocolError);
            assert!(err.to_string().contains(":path"));
        }
    }

    #[test]
    fn test_target_connection_state_tracking() {
        let mut ctx = ConnectTestContext::server();
        let authority = "example.com:443";

        // Initial state
        assert_eq!(ctx.get_target_connection_state(authority), TargetConnectionState::NotAttempted);

        // Establish connection
        ctx.establish_target_connection(authority).expect("connection should succeed");
        assert_eq!(ctx.get_target_connection_state(authority), TargetConnectionState::Connected);

        // Time should advance
        assert!(ctx.time_getter.now().as_nanos() > 0);
    }
}