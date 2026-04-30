#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use std::collections::HashMap;

// Mock HTTP/1.1 connection and request handling for fuzzing
#[derive(Debug, Clone, Arbitrary)]
struct ConnectionCloseTestCase {
    requests: Vec<HttpRequest>,
    connection_headers: Vec<ConnectionHeader>,
    server_behavior: ServerBehaviorTest,
    malformed_scenarios: MalformedScenarios,
}

#[derive(Debug, Clone, Arbitrary)]
struct HttpRequest {
    method: HttpMethod,
    uri: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    connection_directive: ConnectionDirective,
}

#[derive(Debug, Clone, Arbitrary)]
enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
    Connect,
    Trace,
}

#[derive(Debug, Clone, Arbitrary)]
struct ConnectionHeader {
    value: String,
    case_variant: CaseVariant,
    whitespace_pattern: WhitespacePattern,
    multiple_values: bool,
}

#[derive(Debug, Clone, Arbitrary)]
enum CaseVariant {
    Lowercase,        // "connection: close"
    Uppercase,        // "CONNECTION: CLOSE"
    MixedCase,        // "Connection: Close"
    RandomCase,       // "cOnNeCtiOn: cLoSe"
}

#[derive(Debug, Clone, Arbitrary)]
enum WhitespacePattern {
    Normal,           // "Connection: close"
    ExtraSpaces,      // "Connection:  close  "
    NoSpaces,         // "Connection:close"
    Tabs,             // "Connection:\tclose"
    Mixed,            // "Connection: \t close \t"
}

#[derive(Debug, Clone, Arbitrary)]
enum ConnectionDirective {
    Close,
    KeepAlive,
    Upgrade,
    Multiple(Vec<String>), // "close, upgrade"
    Invalid(String),
    Empty,
}

#[derive(Debug, Clone, Arbitrary)]
struct ServerBehaviorTest {
    test_connection_reuse: bool,
    test_pipelined_requests: bool,
    test_final_response_handling: bool,
    test_connection_state_after_close: bool,
}

#[derive(Debug, Clone, Arbitrary)]
struct MalformedScenarios {
    duplicate_connection_headers: bool,
    invalid_header_syntax: bool,
    non_ascii_values: bool,
    extremely_long_values: bool,
    null_bytes_in_headers: bool,
    missing_colon: bool,
    empty_header_name: bool,
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessively large inputs
    if data.len() > 100_000 {
        return;
    }

    let mut u = Unstructured::new(data);

    // Try to generate a test case from the fuzz input
    let test_case = match ConnectionCloseTestCase::arbitrary(&mut u) {
        Ok(case) => case,
        Err(_) => return, // Invalid input for generating test case
    };

    // Test scenario 1: Basic Connection: close handling
    test_basic_connection_close(&test_case);

    // Test scenario 2: Connection close with multiple requests
    test_connection_close_with_multiple_requests(&test_case);

    // Test scenario 3: Connection header case sensitivity
    test_connection_header_case_variants(&test_case);

    // Test scenario 4: Connection close vs keep-alive precedence
    test_close_keepalive_precedence(&test_case);

    // Test scenario 5: Multiple Connection headers
    test_multiple_connection_headers(&test_case);

    // Test scenario 6: Pipelined requests with Connection: close
    test_pipelined_requests_with_close(&test_case);

    // Test scenario 7: Server connection state after close
    test_server_state_after_close(&test_case);

    // Test scenario 8: Malformed Connection headers
    test_malformed_connection_headers(&test_case);

    // Test scenario 9: Connection close with different HTTP methods
    test_connection_close_with_methods(&test_case);

    // Test scenario 10: Final response handling
    test_final_response_handling(&test_case);
});

/// Test basic Connection: close header handling
fn test_basic_connection_close(test_case: &ConnectionCloseTestCase) {
    let mut http_server = create_http_server();

    for request in &test_case.requests {
        if matches!(request.connection_directive, ConnectionDirective::Close) {
            let mut request_headers = request.headers.clone();
            request_headers.push(("Connection".to_string(), "close".to_string()));

            let http_request = format_http_request(request, &request_headers);
            let result = http_server.handle_request(&http_request);

            match result {
                Ok(response) => {
                    // Verify Connection: close is honored in response
                    assert!(
                        response.should_close_connection,
                        "Server should honor Connection: close directive"
                    );

                    // Verify response includes Connection: close header
                    let connection_header = response.headers.get("Connection")
                        .or_else(|| response.headers.get("connection"))
                        .or_else(|| response.headers.get("CONNECTION"));

                    if let Some(conn_value) = connection_header {
                        assert!(
                            conn_value.to_lowercase().contains("close"),
                            "Response should include Connection: close header"
                        );
                    }

                    // Verify server stops accepting new requests on this connection
                    assert!(
                        http_server.connection_should_close,
                        "Server should mark connection for closure"
                    );
                }
                Err(error_msg) => {
                    // Valid Connection: close requests should not fail
                    if is_valid_connection_close_request(request) {
                        assert!(
                            false,
                            "Valid Connection: close request failed: {}",
                            error_msg
                        );
                    }
                }
            }
        }
    }
}

/// Test Connection: close with multiple requests in sequence
fn test_connection_close_with_multiple_requests(test_case: &ConnectionCloseTestCase) {
    let mut http_server = create_http_server();

    let mut close_request_index = None;

    for (i, request) in test_case.requests.iter().enumerate() {
        let mut request_headers = request.headers.clone();

        // Add appropriate Connection header
        match &request.connection_directive {
            ConnectionDirective::Close => {
                request_headers.push(("Connection".to_string(), "close".to_string()));
                close_request_index = Some(i);
            }
            ConnectionDirective::KeepAlive => {
                request_headers.push(("Connection".to_string(), "keep-alive".to_string()));
            }
            ConnectionDirective::Multiple(values) => {
                let combined = values.join(", ");
                request_headers.push(("Connection".to_string(), combined));
                if values.iter().any(|v| v.to_lowercase().contains("close")) {
                    close_request_index = Some(i);
                }
            }
            _ => {}
        }

        let http_request = format_http_request(request, &request_headers);
        let result = http_server.handle_request(&http_request);

        match result {
            Ok(response) => {
                // If this was a close request, connection should be marked for closure
                if close_request_index == Some(i) {
                    assert!(
                        response.should_close_connection,
                        "Connection should close after Connection: close request"
                    );

                    // Subsequent requests should be rejected
                    if i + 1 < test_case.requests.len() {
                        let next_request = &test_case.requests[i + 1];
                        let next_headers = next_request.headers.clone();
                        let next_http_request = format_http_request(next_request, &next_headers);

                        let next_result = http_server.handle_request(&next_http_request);

                        match next_result {
                            Ok(_) => {
                                // If accepted, it should be a new connection
                                assert!(
                                    http_server.is_new_connection(),
                                    "Request after close should require new connection"
                                );
                            }
                            Err(_) => {
                                // Rejection is also valid behavior
                            }
                        }
                    }
                    break; // Stop processing after close
                }
            }
            Err(_) => {
                // Handle request errors appropriately
                break;
            }
        }
    }
}

/// Test Connection header case sensitivity variations
fn test_connection_header_case_variants(test_case: &ConnectionCloseTestCase) {
    for connection_header in &test_case.connection_headers {
        let mut http_server = create_http_server();

        let header_name = format_header_name("Connection", &connection_header.case_variant);
        let header_value = format_header_value("close", &connection_header.whitespace_pattern);

        let request = HttpRequest {
            method: HttpMethod::Get,
            uri: "/test".to_string(),
            headers: vec![(header_name, header_value)],
            body: Vec::new(),
            connection_directive: ConnectionDirective::Close,
        };

        let http_request = format_http_request(&request, &request.headers);
        let result = http_server.handle_request(&http_request);

        match result {
            Ok(response) => {
                // HTTP/1.1 headers should be case-insensitive
                assert!(
                    response.should_close_connection,
                    "Connection: close should work regardless of case: {:?}",
                    connection_header.case_variant
                );
            }
            Err(error_msg) => {
                // Case variations should not cause parsing errors
                assert!(
                    false,
                    "Case variant should not cause error: {} (case: {:?})",
                    error_msg, connection_header.case_variant
                );
            }
        }
    }
}

/// Test precedence between close and keep-alive directives
fn test_close_keepalive_precedence(test_case: &ConnectionCloseTestCase) {
    let mut http_server = create_http_server();

    // Test various combinations of close and keep-alive
    let precedence_tests = vec![
        ("close, keep-alive", true),   // close should take precedence
        ("keep-alive, close", true),   // close should take precedence regardless of order
        ("close", true),               // explicit close
        ("keep-alive", false),         // explicit keep-alive
        ("upgrade, close", true),      // close with other directives
    ];

    for (connection_value, should_close) in precedence_tests {
        let request = HttpRequest {
            method: HttpMethod::Get,
            uri: "/test".to_string(),
            headers: vec![("Connection".to_string(), connection_value.to_string())],
            body: Vec::new(),
            connection_directive: if should_close {
                ConnectionDirective::Close
            } else {
                ConnectionDirective::KeepAlive
            },
        };

        let http_request = format_http_request(&request, &request.headers);
        let result = http_server.handle_request(&http_request);

        match result {
            Ok(response) => {
                assert_eq!(
                    response.should_close_connection, should_close,
                    "Wrong precedence for Connection: {} (expected close: {})",
                    connection_value, should_close
                );
            }
            Err(error_msg) => {
                // Valid connection directives should not fail
                assert!(
                    false,
                    "Valid connection directive failed: {} (value: {})",
                    error_msg, connection_value
                );
            }
        }

        // Reset server for next test
        http_server = create_http_server();
    }
}

/// Test multiple Connection headers in same request
fn test_multiple_connection_headers(test_case: &ConnectionCloseTestCase) {
    if !test_case.malformed_scenarios.duplicate_connection_headers {
        return;
    }

    let mut http_server = create_http_server();

    // Test duplicate Connection headers
    let duplicate_headers = vec![
        ("Connection".to_string(), "keep-alive".to_string()),
        ("Connection".to_string(), "close".to_string()),
        ("connection".to_string(), "upgrade".to_string()), // Different case
    ];

    let request = HttpRequest {
        method: HttpMethod::Get,
        uri: "/test".to_string(),
        headers: duplicate_headers,
        body: Vec::new(),
        connection_directive: ConnectionDirective::Multiple(vec!["keep-alive".to_string(), "close".to_string()]),
    };

    let http_request = format_http_request(&request, &request.headers);
    let result = http_server.handle_request(&http_request);

    match result {
        Ok(response) => {
            // Should handle multiple headers gracefully
            // Close should take precedence when present
            assert!(
                response.should_close_connection,
                "Close directive should take precedence with multiple Connection headers"
            );
        }
        Err(error_msg) => {
            // Multiple headers might be rejected by strict parsers
            assert!(
                error_msg.contains("multiple") ||
                error_msg.contains("duplicate") ||
                error_msg.contains("invalid"),
                "Multiple Connection headers error should be descriptive: {}",
                error_msg
            );
        }
    }
}

/// Test pipelined requests with Connection: close
fn test_pipelined_requests_with_close(test_case: &ConnectionCloseTestCase) {
    if !test_case.server_behavior.test_pipelined_requests {
        return;
    }

    let mut http_server = create_http_server();

    // Simulate pipelined requests where second request has Connection: close
    let pipelined_requests = vec![
        HttpRequest {
            method: HttpMethod::Get,
            uri: "/first".to_string(),
            headers: vec![("Connection".to_string(), "keep-alive".to_string())],
            body: Vec::new(),
            connection_directive: ConnectionDirective::KeepAlive,
        },
        HttpRequest {
            method: HttpMethod::Get,
            uri: "/second".to_string(),
            headers: vec![("Connection".to_string(), "close".to_string())],
            body: Vec::new(),
            connection_directive: ConnectionDirective::Close,
        },
    ];

    for (i, request) in pipelined_requests.iter().enumerate() {
        let http_request = format_http_request(request, &request.headers);
        let result = http_server.handle_request(&http_request);

        match result {
            Ok(response) => {
                if i == 0 {
                    // First request should not close connection
                    assert!(
                        !response.should_close_connection,
                        "First pipelined request should not close connection"
                    );
                } else {
                    // Second request should close connection
                    assert!(
                        response.should_close_connection,
                        "Second request with Connection: close should close connection"
                    );

                    // Server should not accept further requests
                    assert!(
                        http_server.connection_should_close,
                        "Server should mark connection for closure after close directive"
                    );
                }
            }
            Err(_) => {
                // Pipelined request handling might fail for various reasons
                break;
            }
        }
    }
}

/// Test server connection state after Connection: close
fn test_server_state_after_close(test_case: &ConnectionCloseTestCase) {
    if !test_case.server_behavior.test_connection_state_after_close {
        return;
    }

    let mut http_server = create_http_server();

    // Send request with Connection: close
    let close_request = HttpRequest {
        method: HttpMethod::Post,
        uri: "/data".to_string(),
        headers: vec![("Connection".to_string(), "close".to_string())],
        body: b"test data".to_vec(),
        connection_directive: ConnectionDirective::Close,
    };

    let http_request = format_http_request(&close_request, &close_request.headers);
    let result = http_server.handle_request(&http_request);

    match result {
        Ok(response) => {
            // Verify connection is marked for closure
            assert!(
                response.should_close_connection,
                "Response should indicate connection closure"
            );

            // Verify server internal state
            assert!(
                http_server.connection_should_close,
                "Server should internally mark connection for closure"
            );

            assert!(
                !http_server.accepts_new_requests(),
                "Server should not accept new requests after Connection: close"
            );

            // Verify connection cleanup
            http_server.finalize_connection();
            assert!(
                http_server.is_connection_closed(),
                "Connection should be closed after finalization"
            );
        }
        Err(error_msg) => {
            assert!(
                false,
                "Valid Connection: close request should not fail: {}",
                error_msg
            );
        }
    }
}

/// Test malformed Connection headers
fn test_malformed_connection_headers(test_case: &ConnectionCloseTestCase) {
    let malformed_headers = vec![
        // Invalid syntax patterns
        ("Connection", ""),                           // Empty value
        ("Connection", "close\x00null"),             // Null byte
        ("Connection", "close\r\nInjection: bad"),   // Header injection
        ("Connection", " ".repeat(10000).as_str()), // Extremely long value
        ("Connection", "clóse"),                     // Non-ASCII
        ("", "close"),                               // Empty header name
        ("Connection\x00", "close"),                 // Null in header name
        ("Connection\r\n", "close"),                 // CRLF in header name
    ];

    for (header_name, header_value) in malformed_headers {
        let mut http_server = create_http_server();

        let request = HttpRequest {
            method: HttpMethod::Get,
            uri: "/test".to_string(),
            headers: vec![(header_name.to_string(), header_value.to_string())],
            body: Vec::new(),
            connection_directive: ConnectionDirective::Invalid(header_value.to_string()),
        };

        let http_request = format_http_request(&request, &request.headers);
        let result = http_server.handle_request(&http_request);

        match result {
            Ok(response) => {
                // Malformed headers might be ignored or cause default behavior
                // Server should handle gracefully without crashing
            }
            Err(error_msg) => {
                // Malformed headers should be rejected with appropriate error
                assert!(
                    error_msg.contains("invalid") ||
                    error_msg.contains("malformed") ||
                    error_msg.contains("bad request") ||
                    error_msg.contains("400"),
                    "Malformed header should be properly rejected: {} (header: {}={})",
                    error_msg, header_name, header_value
                );
            }
        }
    }
}

/// Test Connection: close with different HTTP methods
fn test_connection_close_with_methods(test_case: &ConnectionCloseTestCase) {
    for request in &test_case.requests {
        let mut http_server = create_http_server();

        if matches!(request.connection_directive, ConnectionDirective::Close) {
            let mut headers = request.headers.clone();
            headers.push(("Connection".to_string(), "close".to_string()));

            let http_request = format_http_request(request, &headers);
            let result = http_server.handle_request(&http_request);

            match result {
                Ok(response) => {
                    // Connection: close should work with all HTTP methods
                    assert!(
                        response.should_close_connection,
                        "Connection: close should work with {:?} method",
                        request.method
                    );

                    // Verify method-specific behavior
                    match request.method {
                        HttpMethod::Head => {
                            // HEAD responses should not have body but should honor connection close
                            assert!(
                                response.body.is_empty(),
                                "HEAD response should not have body"
                            );
                        }
                        HttpMethod::Connect => {
                            // CONNECT might have special handling
                        }
                        _ => {
                            // Other methods should handle connection close normally
                        }
                    }
                }
                Err(error_msg) => {
                    // Some methods might not be supported, but error should be method-related, not connection-related
                    if !error_msg.contains("method") && !error_msg.contains("405") {
                        assert!(
                            false,
                            "Connection: close should not fail for method {:?}: {}",
                            request.method, error_msg
                        );
                    }
                }
            }
        }
    }
}

/// Test final response handling with Connection: close
fn test_final_response_handling(test_case: &ConnectionCloseTestCase) {
    if !test_case.server_behavior.test_final_response_handling {
        return;
    }

    let mut http_server = create_http_server();

    let close_request = HttpRequest {
        method: HttpMethod::Get,
        uri: "/final".to_string(),
        headers: vec![("Connection".to_string(), "close".to_string())],
        body: Vec::new(),
        connection_directive: ConnectionDirective::Close,
    };

    let http_request = format_http_request(&close_request, &close_request.headers);
    let result = http_server.handle_request(&http_request);

    match result {
        Ok(response) => {
            // Verify this is treated as final response
            assert!(
                response.should_close_connection,
                "Final response should indicate connection closure"
            );

            // Verify response is complete and well-formed
            assert!(
                !response.status.is_empty(),
                "Final response should have status"
            );

            assert!(
                response.headers.contains_key("Connection") ||
                response.headers.contains_key("connection"),
                "Final response should include Connection header"
            );

            // Server should prepare for connection closure
            assert!(
                http_server.connection_should_close,
                "Server should prepare for connection closure after final response"
            );

            // Verify no further requests are accepted
            let followup_request = HttpRequest {
                method: HttpMethod::Get,
                uri: "/after-close".to_string(),
                headers: Vec::new(),
                body: Vec::new(),
                connection_directive: ConnectionDirective::KeepAlive,
            };

            let followup_http_request = format_http_request(&followup_request, &followup_request.headers);
            let followup_result = http_server.handle_request(&followup_http_request);

            match followup_result {
                Ok(_) => {
                    // If accepted, should be on new connection
                    assert!(
                        http_server.is_new_connection(),
                        "Request after close should be on new connection"
                    );
                }
                Err(_) => {
                    // Rejection is expected behavior
                }
            }
        }
        Err(error_msg) => {
            assert!(
                false,
                "Final response with Connection: close should not fail: {}",
                error_msg
            );
        }
    }
}

// Helper structures and functions

#[derive(Debug, Clone)]
struct HttpServer {
    connection_should_close: bool,
    connection_state: ConnectionState,
    request_count: usize,
}

#[derive(Debug, Clone, PartialEq)]
enum ConnectionState {
    Open,
    ClosePending,
    Closed,
}

#[derive(Debug)]
struct HttpResponse {
    status: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    should_close_connection: bool,
}

fn create_http_server() -> HttpServer {
    HttpServer {
        connection_should_close: false,
        connection_state: ConnectionState::Open,
        request_count: 0,
    }
}

impl HttpServer {
    fn handle_request(&mut self, request: &str) -> Result<HttpResponse, String> {
        if self.connection_state == ConnectionState::Closed {
            return Err("Connection closed".to_string());
        }

        self.request_count += 1;

        // Parse request
        let (method, headers, body) = parse_http_request(request)?;

        // Check for Connection header
        let mut should_close = false;
        let mut response_headers = HashMap::new();

        for (name, value) in &headers {
            if name.to_lowercase() == "connection" {
                let connection_values: Vec<&str> = value
                    .split(',')
                    .map(|s| s.trim().to_lowercase())
                    .map(|s| s.as_str())
                    .collect();

                if connection_values.iter().any(|&v| v == "close") {
                    should_close = true;
                    response_headers.insert("Connection".to_string(), "close".to_string());
                } else if connection_values.iter().any(|&v| v == "keep-alive") {
                    response_headers.insert("Connection".to_string(), "keep-alive".to_string());
                }
                break;
            }
        }

        // Update server state
        if should_close {
            self.connection_should_close = true;
            self.connection_state = ConnectionState::ClosePending;
        }

        // Generate response
        let response_body = if method.to_uppercase() == "HEAD" {
            Vec::new()
        } else {
            format!("Response for {} request", method).into_bytes()
        };

        response_headers.insert("Content-Length".to_string(), response_body.len().to_string());
        response_headers.insert("Server".to_string(), "TestServer/1.0".to_string());

        Ok(HttpResponse {
            status: "200 OK".to_string(),
            headers: response_headers,
            body: response_body,
            should_close_connection: should_close,
        })
    }

    fn accepts_new_requests(&self) -> bool {
        !self.connection_should_close && self.connection_state == ConnectionState::Open
    }

    fn is_new_connection(&self) -> bool {
        self.request_count <= 1
    }

    fn finalize_connection(&mut self) {
        self.connection_state = ConnectionState::Closed;
    }

    fn is_connection_closed(&self) -> bool {
        self.connection_state == ConnectionState::Closed
    }
}

fn format_http_request(request: &HttpRequest, headers: &[(String, String)]) -> String {
    let method_str = format!("{:?}", request.method).to_uppercase();
    let mut request_str = format!("{} {} HTTP/1.1\r\n", method_str, request.uri);

    for (name, value) in headers {
        request_str.push_str(&format!("{}: {}\r\n", name, value));
    }

    request_str.push_str("\r\n");

    if !request.body.is_empty() {
        request_str.push_str(&String::from_utf8_lossy(&request.body));
    }

    request_str
}

fn parse_http_request(request: &str) -> Result<(String, Vec<(String, String)>, Vec<u8>), String> {
    let mut lines = request.lines();

    // Parse request line
    let request_line = lines.next().ok_or("Missing request line")?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err("Invalid request line".to_string());
    }
    let method = parts[0].to_string();

    // Parse headers
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break; // End of headers
        }

        if let Some(colon_pos) = line.find(':') {
            let name = line[..colon_pos].trim().to_string();
            let value = line[colon_pos + 1..].trim().to_string();

            // Basic header validation
            if name.is_empty() {
                return Err("Empty header name".to_string());
            }

            if name.contains('\0') || value.contains('\0') {
                return Err("Null byte in header".to_string());
            }

            if name.contains('\r') || name.contains('\n') || value.contains('\r') || value.contains('\n') {
                return Err("CRLF in header".to_string());
            }

            headers.push((name, value));
        } else {
            return Err("Invalid header format".to_string());
        }
    }

    let body = Vec::new(); // Simplified - no body parsing for this fuzzer

    Ok((method, headers, body))
}

fn format_header_name(name: &str, case_variant: &CaseVariant) -> String {
    match case_variant {
        CaseVariant::Lowercase => name.to_lowercase(),
        CaseVariant::Uppercase => name.to_uppercase(),
        CaseVariant::MixedCase => {
            name.chars()
                .enumerate()
                .map(|(i, c)| if i == 0 { c.to_uppercase().to_string() } else { c.to_lowercase().to_string() })
                .collect::<String>()
        }
        CaseVariant::RandomCase => {
            name.chars()
                .enumerate()
                .map(|(i, c)| if i % 2 == 0 { c.to_lowercase().to_string() } else { c.to_uppercase().to_string() })
                .collect::<String>()
        }
    }
}

fn format_header_value(value: &str, whitespace_pattern: &WhitespacePattern) -> String {
    match whitespace_pattern {
        WhitespacePattern::Normal => value.to_string(),
        WhitespacePattern::ExtraSpaces => format!("  {}  ", value),
        WhitespacePattern::NoSpaces => value.replace(" ", ""),
        WhitespacePattern::Tabs => format!("\t{}\t", value),
        WhitespacePattern::Mixed => format!(" \t {} \t ", value),
    }
}

fn is_valid_connection_close_request(request: &HttpRequest) -> bool {
    matches!(request.connection_directive, ConnectionDirective::Close) &&
    !request.headers.iter().any(|(name, value)| {
        name.is_empty() ||
        value.contains('\0') ||
        name.contains('\0') ||
        name.contains('\r') || name.contains('\n') ||
        value.contains('\r') || value.contains('\n')
    })
}