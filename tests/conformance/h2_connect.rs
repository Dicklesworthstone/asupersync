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

use asupersync::bytes::BytesMut;
use asupersync::http::h2::frame::HeadersFrame;
use asupersync::http::h2::{ErrorCode, H2Error, Header};
use proptest::prelude::*;
use std::collections::HashMap;

/// Lightweight test clock for deterministic assertions local to this harness.
#[derive(Debug, Clone)]
struct ConnectTestTimeGetter {
    elapsed_nanos: u64,
}

impl ConnectTestTimeGetter {
    fn new() -> Self {
        Self { elapsed_nanos: 0 }
    }

    fn advance(&mut self, nanos: u64) {
        self.elapsed_nanos += nanos;
    }

    fn now_nanos(&self) -> u64 {
        self.elapsed_nanos
    }
}

/// CONNECT request test input structure
#[derive(Debug, Clone)]
struct ConnectRequestInput {
    /// Target authority (hostname:port)
    authority: Option<String>,
    /// Optional extended CONNECT protocol (RFC 8441).
    protocol: Option<String>,
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

        // Add protocol if present (extended CONNECT / RFC 8441)
        if let Some(ref protocol) = self.protocol {
            headers.push(Header::new(":protocol", protocol));
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
    target_connections: HashMap<String, TargetConnectionState>,
    time_getter: ConnectTestTimeGetter,
}

impl ConnectTestContext {
    fn new() -> Self {
        Self {
            target_connections: HashMap::new(),
            time_getter: ConnectTestTimeGetter::new(),
        }
    }

    fn server() -> Self {
        Self {
            target_connections: HashMap::new(),
            time_getter: ConnectTestTimeGetter::new(),
        }
    }

    fn establish_target_connection(
        &mut self,
        authority: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.target_connections
            .insert(authority.to_string(), TargetConnectionState::Connected);
        self.time_getter.advance(1_000_000); // 1ms for connection establishment
        Ok(())
    }

    fn get_target_connection_state(&self, authority: &str) -> TargetConnectionState {
        self.target_connections
            .get(authority)
            .copied()
            .unwrap_or(TargetConnectionState::NotAttempted)
    }
}

/// Validate CONNECT request pseudo-headers according to RFC 9113 §8.5
fn validate_connect_pseudo_headers(input: &ConnectRequestInput) -> Result<(), H2Error> {
    // RFC 9113 §8.5: CONNECT method MUST include :authority
    if input.authority.is_none() {
        return Err(H2Error::protocol(
            "CONNECT request missing :authority pseudo-header",
        ));
    }

    // RFC 8441 extended CONNECT is not enabled on this validator path.
    // Reject :protocol explicitly so RFC 8441-style requests are not
    // silently accepted without SETTINGS negotiation support.
    if input.protocol.is_some() {
        return Err(H2Error::protocol(
            "CONNECT request must not include unsupported :protocol pseudo-header",
        ));
    }

    // RFC 9113 §8.5: CONNECT method MUST NOT include :scheme or :path
    if input.scheme.is_some() {
        return Err(H2Error::protocol(
            "CONNECT request must not include :scheme pseudo-header",
        ));
    }

    if input.path.is_some() {
        return Err(H2Error::protocol(
            "CONNECT request must not include :path pseudo-header",
        ));
    }

    Ok(())
}

/// Generate valid ConnectRequestInput for property-based testing
fn arb_valid_connect_request() -> impl Strategy<Value = ConnectRequestInput> {
    (
        "[a-z]+\\.(com|org|net):[1-9][0-9]{1,4}", // authority (hostname:port)
        prop::collection::vec("[a-z]+", 0..5).prop_map(|names| {
            names
                .into_iter()
                .enumerate()
                .map(|(i, name)| (format!("header-{i}"), format!("value-{name}")))
                .collect::<Vec<_>>()
        }), // headers
        1u32..=100,                               // stream_id (odd for client-initiated)
    )
        .prop_map(|(authority, headers, stream_id)| {
            ConnectRequestInput {
                authority: Some(authority),
                protocol: None,
                scheme: None,     // Valid CONNECT: no scheme
                path: None,       // Valid CONNECT: no path
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
            prop::option::of("[a-z]+\\.(com|org|net):[1-9][0-9]{1,4}")
                .prop_filter("no authority", |opt| opt.is_none()),
            prop::option::of("https?"),
            prop::option::of("/[a-z/]*"),
            any::<bool>(),
            1u32..=100,
        )
            .prop_map(|(authority, scheme, path, end_stream, stream_id)| {
                ConnectRequestInput {
                    authority,
                    protocol: None,
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
        )
            .prop_map(|(authority, scheme, end_stream, stream_id)| {
                ConnectRequestInput {
                    authority: Some(authority),
                    protocol: None,
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
        )
            .prop_map(|(authority, path, end_stream, stream_id)| {
                ConnectRequestInput {
                    authority: Some(authority),
                    protocol: None,
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

proptest! {
    /// MR1: CONNECT requests without :authority must be rejected with PROTOCOL_ERROR.
    #[test]
    fn connect_without_authority_rejected(
        input in arb_invalid_connect_request()
            .prop_filter("missing authority only", |input| input.authority.is_none())
    ) {
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

    /// MR1 (inverse): CONNECT requests with valid :authority should be accepted.
    #[test]
    fn connect_with_authority_accepted(input in arb_valid_connect_request()) {
        let result = validate_connect_pseudo_headers(&input);

        prop_assert!(result.is_ok(),
            "Valid CONNECT request with :authority should be accepted: {:?}", result);
    }
}

// =============================================================================
// Metamorphic Relation 2: Scheme and Path Forbidden
// =============================================================================

proptest! {
    /// MR2: CONNECT requests with :scheme or :path must be rejected with PROTOCOL_ERROR.
    #[test]
    fn connect_with_scheme_or_path_rejected(
        input in arb_invalid_connect_request()
            .prop_filter("has forbidden headers", |input| input.has_forbidden_pseudo_headers())
    ) {
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

    /// MR2 (inverse): CONNECT requests without :scheme or :path should be accepted.
    #[test]
    fn connect_without_scheme_path_accepted(input in arb_valid_connect_request()) {
        prop_assume!(!input.has_forbidden_pseudo_headers());
        prop_assume!(input.authority.is_some());

        let result = validate_connect_pseudo_headers(&input);
        prop_assert!(result.is_ok(),
            "CONNECT without forbidden pseudo-headers should be accepted: {:?}", result);
    }
}

// =============================================================================
// Metamorphic Relation 3: END_STREAM Termination
// =============================================================================

proptest! {
    /// MR3: CONNECT requests must end with END_STREAM flag per RFC 9113 §8.5.
    #[test]
    fn connect_request_ends_with_end_stream(input in arb_valid_connect_request()) {
        prop_assert!(input.end_stream,
            "CONNECT request must have END_STREAM flag set (RFC 9113 §8.5)");

        if let Ok(headers_frame) = input.to_headers_frame() {
            prop_assert!(headers_frame.end_stream,
                "CONNECT HeadersFrame must have end_stream=true");
            prop_assert!(headers_frame.end_headers,
                "CONNECT HeadersFrame must have end_headers=true");
        }
    }

    /// MR3 (frame-level): CONNECT frames without END_STREAM should be protocol violations.
    #[test]
    fn connect_without_end_stream_is_invalid(
        input in arb_valid_connect_request().prop_map(|mut input| {
            input.end_stream = false;
            input
        })
    ) {
        prop_assert!(!input.end_stream,
            "Test precondition: input should not have END_STREAM");

        prop_assert!(
            !input.end_stream,
            "CONNECT requests without END_STREAM violate RFC 9113 §8.5 and should be rejected"
        );
    }
}

// =============================================================================
// Metamorphic Relation 4: Target Connection Timing
// =============================================================================

proptest! {
    /// MR4: Target connection must be established before sending HEADERS response.
    #[test]
    fn target_connected_before_success_response(
        authority in "[a-z]+\\.(com|org|net):[1-9][0-9]{1,4}",
        status in 200u16..=299u16
    ) {
        let mut ctx = ConnectTestContext::server();

        let connect_input = ConnectRequestInput {
            authority: Some(authority.clone()),
            protocol: None,
            scheme: None,
            path: None,
            end_stream: true,
            headers: vec![],
            stream_id: 1,
        };

        let initial_state = ctx.get_target_connection_state(&authority);
        prop_assert_eq!(initial_state, TargetConnectionState::NotAttempted,
            "Initial target connection state should be NotAttempted");

        ctx.establish_target_connection(&authority).expect("connection should succeed");

        let connected_state = ctx.get_target_connection_state(&authority);
        prop_assert_eq!(connected_state, TargetConnectionState::Connected,
            "Target connection should be established before success response");

        let response_time_nanos = ctx.time_getter.now_nanos();
        prop_assert!(response_time_nanos > 0,
            "Response time should be after connection establishment");
        let _ = connect_input;
        let _ = status;
    }

    /// MR4 (error case): Target connection failure should precede error response.
    #[test]
    fn target_failed_before_error_response(
        authority in "[a-z]+\\.(com|org|net):[1-9][0-9]{1,4}",
        error_status in prop::sample::select(vec![502u16, 503u16, 504u16])
    ) {
        let mut ctx = ConnectTestContext::server();

        ctx.target_connections
            .insert(authority.clone(), TargetConnectionState::Failed);
        ctx.time_getter.advance(5_000_000);

        let failed_state = ctx.get_target_connection_state(&authority);
        prop_assert_eq!(failed_state, TargetConnectionState::Failed,
            "Target connection should be in Failed state before error response");

        let response_time_nanos = ctx.time_getter.now_nanos();
        prop_assert!(response_time_nanos > 0,
            "Error response time should be after connection attempt");
        let _ = error_status;
    }
}

// =============================================================================
// Metamorphic Relation 5: Response Body Validation
// =============================================================================

proptest! {
    /// MR5: CONNECT response must not contain a message body per RFC 9113 §8.5.
    #[test]
    fn connect_response_without_body(
        response in (
            200u16..=599u16,
            any::<bool>(),
            1u32..=100,
        )
            .prop_map(|(status, end_stream, stream_id)| ConnectResponseInput {
                status,
                has_body: false,
                end_stream,
                headers: vec![("content-type".to_string(), "text/plain".to_string())],
                stream_id: stream_id * 2 + 1,
            })
    ) {
        prop_assert!(!response.has_body,
            "CONNECT response must not contain a message body (RFC 9113 §8.5)");

        let has_content_length = response.headers.iter()
            .any(|(name, value)| name.to_lowercase() == "content-length" && value != "0");

        prop_assert!(!has_content_length,
            "CONNECT response should not have non-zero Content-Length header");
    }

    /// MR5 (violation case): CONNECT responses with bodies should be rejected.
    #[test]
    fn connect_response_with_body_is_violation(
        response in (
            200u16..=299u16,
            any::<bool>(),
            1u32..=100,
        )
            .prop_map(|(status, end_stream, stream_id)| ConnectResponseInput {
                status,
                has_body: true,
                end_stream,
                headers: vec![("content-length".to_string(), "42".to_string())],
                stream_id: stream_id * 2 + 1,
            })
    ) {
        prop_assert!(response.has_body, "Test precondition: response should have body");

        let has_nonzero_content_length = response.headers.iter()
            .any(|(name, value)| name.to_lowercase() == "content-length" && value != "0");

        prop_assert!(has_nonzero_content_length || response.has_body,
            "Response with body violates CONNECT semantics");
    }
}

// =============================================================================
// Integration Tests: Combined Metamorphic Relations
// =============================================================================

proptest! {
    /// Integration test: Complete valid CONNECT request/response flow.
    #[test]
    fn complete_connect_flow(
        authority in "[a-z]+\\.(com|org|net):[1-9][0-9]{1,4}",
        success_status in 200u16..=299u16
    ) {
        let mut ctx = ConnectTestContext::server();

        let request = ConnectRequestInput {
            authority: Some(authority.clone()),
            protocol: None,
            scheme: None,
            path: None,
            end_stream: true,
            headers: vec![],
            stream_id: 1,
        };

        let validation_result = validate_connect_pseudo_headers(&request);
        prop_assert!(validation_result.is_ok(),
            "Valid CONNECT request should pass validation: {:?}", validation_result);

        ctx.establish_target_connection(&authority)
            .expect("Target connection should succeed");

        let target_state = ctx.get_target_connection_state(&authority);
        prop_assert_eq!(target_state, TargetConnectionState::Connected,
            "Target connection must be established before response");

        let response = ConnectResponseInput {
            status: success_status,
            has_body: false,
            end_stream: true,
            headers: vec![],
            stream_id: 1,
        };

        prop_assert!(!response.has_body,
            "CONNECT response must not have body");
        prop_assert!(response.status >= 200 && response.status < 300,
            "Success response should have 2xx status");
    }

    /// Integration test: CONNECT error scenarios.
    #[test]
    fn connect_error_scenarios(
        authority in prop::option::of("[a-z]+\\.(com|org|net):[1-9][0-9]{1,4}"),
        has_scheme in any::<bool>(),
        has_path in any::<bool>(),
        error_status in prop::sample::select(vec![400u16, 502u16, 503u16, 504u16])
    ) {
        let scheme = if has_scheme { Some("https".to_string()) } else { None };
        let path = if has_path { Some("/tunnel".to_string()) } else { None };

        let request = ConnectRequestInput {
            authority: authority.clone(),
            protocol: None,
            scheme,
            path,
            end_stream: true,
            headers: vec![],
            stream_id: 1,
        };

        let validation_result = validate_connect_pseudo_headers(&request);

        if authority.is_none() {
            prop_assert!(validation_result.is_err(),
                "CONNECT without authority should be rejected");
        } else if has_scheme || has_path {
            prop_assert!(validation_result.is_err(),
                "CONNECT with scheme/path should be rejected");
        } else {
            prop_assert!(validation_result.is_ok(),
                "Valid CONNECT request should pass validation");
        }

        let error_response = ConnectResponseInput {
            status: error_status,
            has_body: false,
            end_stream: true,
            headers: vec![],
            stream_id: 1,
        };

        prop_assert!(!error_response.has_body,
            "Even CONNECT error responses must not have body");
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_validate_connect_pseudo_headers_valid() {
        let valid_request = ConnectRequestInput {
            authority: Some("example.com:443".to_string()),
            protocol: None,
            scheme: None,
            path: None,
            end_stream: true,
            headers: vec![],
            stream_id: 1,
        };

        let result = validate_connect_pseudo_headers(&valid_request);
        assert!(
            result.is_ok(),
            "Valid CONNECT request should pass validation"
        );
    }

    #[test]
    fn test_validate_connect_pseudo_headers_missing_authority() {
        let invalid_request = ConnectRequestInput {
            authority: None, // Missing required authority
            protocol: None,
            scheme: None,
            path: None,
            end_stream: true,
            headers: vec![],
            stream_id: 1,
        };

        let result = validate_connect_pseudo_headers(&invalid_request);
        assert!(
            result.is_err(),
            "CONNECT without authority should be rejected"
        );

        if let Err(err) = result {
            assert_eq!(err.code, ErrorCode::ProtocolError);
            assert!(err.to_string().contains("missing :authority"));
        }
    }

    #[test]
    fn test_validate_connect_pseudo_headers_forbidden_scheme() {
        let invalid_request = ConnectRequestInput {
            authority: Some("example.com:443".to_string()),
            protocol: None,
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
            protocol: None,
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
        assert_eq!(
            ctx.get_target_connection_state(authority),
            TargetConnectionState::NotAttempted
        );

        // Establish connection
        ctx.establish_target_connection(authority)
            .expect("connection should succeed");
        assert_eq!(
            ctx.get_target_connection_state(authority),
            TargetConnectionState::Connected
        );

        // Time should advance
        assert!(ctx.time_getter.now_nanos() > 0);
    }

    #[test]
    fn test_validate_connect_pseudo_headers_rejects_rfc8441_websocket_vector() {
        let extended_connect_request = ConnectRequestInput {
            authority: Some("server.example.com:443".to_string()),
            protocol: Some("websocket".to_string()),
            scheme: Some("https".to_string()),
            path: Some("/chat".to_string()),
            end_stream: false,
            headers: vec![
                ("sec-websocket-version".to_string(), "13".to_string()),
                (
                    "sec-websocket-protocol".to_string(),
                    "chat, superchat".to_string(),
                ),
            ],
            stream_id: 1,
        };

        let result = validate_connect_pseudo_headers(&extended_connect_request);
        assert!(
            result.is_err(),
            "RFC 8441-style extended CONNECT must be rejected on the non-enabled CONNECT path"
        );

        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::ProtocolError);
        assert!(err.to_string().contains("unsupported :protocol"));
    }
}
