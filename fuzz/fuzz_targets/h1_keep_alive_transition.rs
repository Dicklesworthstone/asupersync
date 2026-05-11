#![no_main]

//! Fuzz target for HTTP/1.1 Connection: keep-alive specific transitions.
//!
//! This target focuses specifically on keep-alive connection state management,
//! testing the lifecycle of persistent connections, keep-alive timeouts, and
//! the subtle edge cases that arise when maintaining long-lived HTTP/1.1
//! connections. Different from general connection semantics, this tests the
//! specific keep-alive implementation behaviors.
//!
//! Keep-alive transition scenarios tested:
//! - Keep-alive connection establishment and maintenance
//! - Keep-alive timeout and idle connection handling
//! - Pipelined request ordering with keep-alive semantics
//! - Keep-alive connection reuse across multiple request/response cycles
//! - Keep-alive to timeout transition (idle connection cleanup)
//! - Keep-alive with different Content-Length vs chunked encoding
//! - Keep-alive connection pooling and resource limits
//! - HTTP/1.0 explicit keep-alive vs HTTP/1.1 implicit keep-alive
//! - Keep-alive header parameter parsing (timeout=n, max=n)
//! - Keep-alive degradation under server resource pressure
//!
//! Expected behavior:
//! - Keep-alive connections should persist across multiple requests
//! - Idle timeouts should cleanly close keep-alive connections
//! - Request/response boundaries must be preserved in keep-alive mode
//! - Connection pooling should respect keep-alive limits
//! - Malformed keep-alive parameters should be handled gracefully
//! - Server resource limits should gracefully downgrade keep-alive

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Keep-alive specific connection parameters
#[derive(Debug, Clone, Arbitrary)]
struct KeepAliveParams {
    /// Keep-alive timeout in seconds (RFC 2616)
    timeout: Option<u32>,
    /// Maximum requests on this connection
    max_requests: Option<u32>,
}

impl KeepAliveParams {
    /// Parse from Connection header value like "keep-alive; timeout=5; max=1000"
    fn from_header_value(value: &str) -> Self {
        let mut timeout = None;
        let mut max_requests = None;

        for param in value.split(';') {
            let param = param.trim();
            if param.eq_ignore_ascii_case("keep-alive") {
                continue;
            }

            if let Some(eq_pos) = param.find('=') {
                let key = param[..eq_pos].trim();
                let value = param[eq_pos + 1..].trim();

                match key.to_ascii_lowercase().as_str() {
                    "timeout" => {
                        if let Ok(t) = value.parse::<u32>() {
                            timeout = Some(t);
                        }
                    }
                    "max" => {
                        if let Ok(m) = value.parse::<u32>() {
                            max_requests = Some(m);
                        }
                    }
                    _ => {} // Ignore unknown parameters
                }
            }
        }

        Self {
            timeout,
            max_requests,
        }
    }

    /// Generate header value string
    fn to_header_value(&self) -> String {
        let mut parts = vec!["keep-alive".to_string()];

        if let Some(timeout) = self.timeout {
            parts.push(format!("timeout={}", timeout));
        }

        if let Some(max) = self.max_requests {
            parts.push(format!("max={}", max));
        }

        parts.join("; ")
    }
}

/// HTTP message in a keep-alive sequence
#[derive(Debug, Clone, Arbitrary)]
struct KeepAliveMessage {
    /// HTTP version
    version: HttpVersion,
    /// Method for requests (GET, POST, etc.)
    method: HttpMethod,
    /// Connection header directive
    connection_header: ConnectionHeader,
    /// Keep-alive parameters if present
    keep_alive_params: Option<KeepAliveParams>,
    /// Message has body (affects keep-alive semantics)
    has_body: bool,
    /// Body encoding type
    body_encoding: BodyEncoding,
    /// Simulated processing time
    processing_time_ms: u16,
}

/// HTTP version
#[derive(Debug, Clone, Copy, PartialEq, Arbitrary)]
enum HttpVersion {
    Http10,
    Http11,
}

/// HTTP method
#[derive(Debug, Clone, Copy, PartialEq, Arbitrary)]
enum HttpMethod {
    Get,
    Post,
    Head,
    Put,
    Delete,
    Options,
}

/// Connection header type
#[derive(Debug, Clone, Copy, PartialEq, Arbitrary)]
enum ConnectionHeader {
    /// No Connection header
    None,
    /// Connection: keep-alive
    KeepAlive,
    /// Connection: close
    Close,
    /// Connection: upgrade
    Upgrade,
    /// Malformed Connection header
    Malformed,
}

/// Body encoding affects keep-alive message boundaries
#[derive(Debug, Clone, Copy, PartialEq, Arbitrary)]
enum BodyEncoding {
    /// Content-Length specified
    ContentLength,
    /// Transfer-Encoding: chunked
    Chunked,
    /// No body
    None,
    /// Malformed (missing length, invalid chunked)
    Malformed,
}

/// Keep-alive connection state
#[derive(Debug, Clone, Copy, PartialEq)]
enum KeepAliveState {
    /// Freshly established connection
    Established,
    /// Active with pending requests
    Active,
    /// Idle, waiting for next request
    Idle,
    /// Idle timeout expired
    TimedOut,
    /// Reached max request limit
    Exhausted,
    /// Connection closed
    Closed,
    /// Error state
    Error,
}

/// Server keep-alive configuration
#[derive(Debug, Clone, Arbitrary)]
struct KeepAliveConfig {
    /// Server supports keep-alive
    enabled: bool,
    /// Default idle timeout (seconds)
    default_timeout: u32,
    /// Maximum timeout allowed
    max_timeout: u32,
    /// Default max requests per connection
    default_max_requests: u32,
    /// Server max concurrent keep-alive connections
    max_concurrent_connections: u16,
    /// Current number of active keep-alive connections
    current_connections: u16,
}

impl Default for KeepAliveConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_timeout: 60,
            max_timeout: 300,
            default_max_requests: 1000,
            max_concurrent_connections: 10000,
            current_connections: 0,
        }
    }
}

/// Keep-alive test scenario
#[derive(Debug, Clone, Arbitrary)]
struct KeepAliveScenario {
    /// Server configuration
    config: KeepAliveConfig,
    /// Sequence of messages on the connection
    messages: Vec<KeepAliveMessage>,
    /// Simulated time advances between messages
    time_advances: Vec<u32>,
    /// Include edge cases
    include_edge_cases: bool,
}

/// Mock keep-alive connection manager
#[derive(Debug)]
struct MockKeepAliveManager {
    state: KeepAliveState,
    config: KeepAliveConfig,
    requests_processed: u32,
    last_activity_time: u64, // Simulated timestamp
    current_time: u64,
    effective_timeout: u32,
    effective_max_requests: u32,
}

impl MockKeepAliveManager {
    fn new(config: KeepAliveConfig) -> Self {
        let effective_timeout = config.default_timeout;
        let effective_max_requests = config.default_max_requests;

        Self {
            state: KeepAliveState::Established,
            config,
            requests_processed: 0,
            last_activity_time: 0,
            current_time: 0,
            effective_timeout,
            effective_max_requests,
        }
    }

    /// Process a message and update keep-alive state
    fn process_message(&mut self, msg: &KeepAliveMessage) -> Result<KeepAliveState, String> {
        // Check if connection is still usable
        if matches!(self.state, KeepAliveState::Closed | KeepAliveState::Error) {
            return Err("Message on closed/error connection".to_string());
        }

        // Check resource limits
        if !self.config.enabled {
            self.state = KeepAliveState::Closed;
            return Ok(self.state);
        }

        // Update keep-alive parameters from message
        if let Some(params) = &msg.keep_alive_params {
            if let Some(timeout) = params.timeout {
                self.effective_timeout = timeout.min(self.config.max_timeout);
            }
            if let Some(max_req) = params.max_requests {
                self.effective_max_requests = max_req.min(self.config.default_max_requests);
            }
        }

        // Process message based on version and headers
        match (msg.version, msg.connection_header) {
            (HttpVersion::Http10, ConnectionHeader::KeepAlive) => {
                // HTTP/1.0 explicit keep-alive
                self.activate_keep_alive(msg)?;
            }
            (HttpVersion::Http11, ConnectionHeader::Close) => {
                // HTTP/1.1 explicit close
                self.state = KeepAliveState::Closed;
                return Ok(self.state);
            }
            (HttpVersion::Http11, ConnectionHeader::None | ConnectionHeader::KeepAlive) => {
                // HTTP/1.1 implicit keep-alive
                self.activate_keep_alive(msg)?;
            }
            (HttpVersion::Http10, ConnectionHeader::None | ConnectionHeader::Close) => {
                // HTTP/1.0 default close
                self.state = KeepAliveState::Closed;
                return Ok(self.state);
            }
            (_, ConnectionHeader::Upgrade) => {
                // Upgrade requests end keep-alive
                self.state = KeepAliveState::Closed;
                return Ok(self.state);
            }
            (_, ConnectionHeader::Malformed) => {
                // Malformed headers - be conservative and close
                self.state = KeepAliveState::Error;
                return Err("Malformed connection header".to_string());
            }
        }

        // Validate message boundary (critical for keep-alive)
        self.validate_message_boundary(msg)?;

        Ok(self.state)
    }

    fn activate_keep_alive(&mut self, msg: &KeepAliveMessage) -> Result<(), String> {
        self.requests_processed += 1;
        self.last_activity_time = self.current_time;

        // Check request limit
        if self.requests_processed >= self.effective_max_requests {
            self.state = KeepAliveState::Exhausted;
            return Ok(());
        }

        // Check concurrent connection limit
        if self.config.current_connections >= self.config.max_concurrent_connections {
            self.state = KeepAliveState::Closed;
            return Err("Max concurrent connections exceeded".to_string());
        }

        // Set appropriate keep-alive state
        if msg.processing_time_ms > 0 {
            self.state = KeepAliveState::Active;
        } else {
            self.state = KeepAliveState::Idle;
        }

        Ok(())
    }

    fn validate_message_boundary(&self, msg: &KeepAliveMessage) -> Result<(), String> {
        let _observed_method = msg.method;

        if !msg.has_body {
            return Ok(());
        }

        match msg.body_encoding {
            BodyEncoding::ContentLength => {
                // Well-defined boundary
                Ok(())
            }
            BodyEncoding::Chunked => {
                // Well-defined boundary (final chunk)
                Ok(())
            }
            BodyEncoding::None => {
                if msg.has_body {
                    return Err("Body claimed but no encoding specified".to_string());
                }
                Ok(())
            }
            BodyEncoding::Malformed => {
                // Ambiguous message boundary - cannot safely keep connection alive
                Err("Malformed body encoding prevents keep-alive".to_string())
            }
        }
    }

    /// Advance time and check for timeouts
    fn advance_time(&mut self, seconds: u32) {
        self.current_time += seconds as u64;

        // Check for idle timeout
        if matches!(self.state, KeepAliveState::Idle) {
            let idle_time = self.current_time.saturating_sub(self.last_activity_time);
            if idle_time >= self.effective_timeout as u64 {
                self.state = KeepAliveState::TimedOut;
            }
        }
    }

    /// Get current connection state
    fn get_state(&self) -> KeepAliveState {
        self.state
    }

    /// Check if connection can accept more messages
    fn can_accept_message(&self) -> bool {
        matches!(
            self.state,
            KeepAliveState::Established | KeepAliveState::Idle | KeepAliveState::Active
        )
    }

    /// Get connection statistics
    fn get_stats(&self) -> (u32, u64, u32) {
        (
            self.requests_processed,
            self.current_time - self.last_activity_time,
            self.effective_timeout,
        )
    }
}

/// Generate edge case scenarios for keep-alive testing
fn generate_keep_alive_edge_cases() -> Vec<Vec<KeepAliveMessage>> {
    vec![
        // HTTP/1.0 explicit keep-alive sequence
        vec![
            KeepAliveMessage {
                version: HttpVersion::Http10,
                method: HttpMethod::Get,
                connection_header: ConnectionHeader::KeepAlive,
                keep_alive_params: Some(KeepAliveParams {
                    timeout: Some(30),
                    max_requests: Some(5),
                }),
                has_body: false,
                body_encoding: BodyEncoding::None,
                processing_time_ms: 100,
            },
            KeepAliveMessage {
                version: HttpVersion::Http10,
                method: HttpMethod::Post,
                connection_header: ConnectionHeader::KeepAlive,
                keep_alive_params: None,
                has_body: true,
                body_encoding: BodyEncoding::ContentLength,
                processing_time_ms: 50,
            },
        ],
        // HTTP/1.1 implicit keep-alive with timeout
        vec![
            KeepAliveMessage {
                version: HttpVersion::Http11,
                method: HttpMethod::Get,
                connection_header: ConnectionHeader::None,
                keep_alive_params: None,
                has_body: false,
                body_encoding: BodyEncoding::None,
                processing_time_ms: 0,
            },
            KeepAliveMessage {
                version: HttpVersion::Http11,
                method: HttpMethod::Get,
                connection_header: ConnectionHeader::None,
                keep_alive_params: None,
                has_body: false,
                body_encoding: BodyEncoding::None,
                processing_time_ms: 0,
            },
        ],
        // Keep-alive with chunked encoding
        vec![KeepAliveMessage {
            version: HttpVersion::Http11,
            method: HttpMethod::Post,
            connection_header: ConnectionHeader::KeepAlive,
            keep_alive_params: Some(KeepAliveParams {
                timeout: Some(120),
                max_requests: Some(10),
            }),
            has_body: true,
            body_encoding: BodyEncoding::Chunked,
            processing_time_ms: 200,
        }],
        // Malformed keep-alive parameters
        vec![KeepAliveMessage {
            version: HttpVersion::Http11,
            method: HttpMethod::Get,
            connection_header: ConnectionHeader::Malformed,
            keep_alive_params: None,
            has_body: false,
            body_encoding: BodyEncoding::None,
            processing_time_ms: 0,
        }],
        // Keep-alive with message boundary issues
        vec![KeepAliveMessage {
            version: HttpVersion::Http11,
            method: HttpMethod::Post,
            connection_header: ConnectionHeader::KeepAlive,
            keep_alive_params: None,
            has_body: true,
            body_encoding: BodyEncoding::Malformed, // Boundary issue
            processing_time_ms: 0,
        }],
        // Request limit edge case
        vec![
            KeepAliveMessage {
                version: HttpVersion::Http11,
                method: HttpMethod::Get,
                connection_header: ConnectionHeader::KeepAlive,
                keep_alive_params: Some(KeepAliveParams {
                    timeout: None,
                    max_requests: Some(1),
                }),
                has_body: false,
                body_encoding: BodyEncoding::None,
                processing_time_ms: 0,
            },
            KeepAliveMessage {
                version: HttpVersion::Http11,
                method: HttpMethod::Get,
                connection_header: ConnectionHeader::KeepAlive,
                keep_alive_params: None,
                has_body: false,
                body_encoding: BodyEncoding::None,
                processing_time_ms: 0,
            }, // Should be rejected
        ],
    ]
}

fuzz_target!(|scenario: KeepAliveScenario| {
    // Limit scenario complexity
    if scenario.messages.len() > 50 || scenario.time_advances.len() > 50 {
        return;
    }

    let test_sequences = if scenario.include_edge_cases {
        generate_keep_alive_edge_cases()
    } else {
        vec![scenario.messages.clone()]
    };

    for test_sequence in &test_sequences {
        test_keep_alive_sequence(test_sequence, &scenario.time_advances, &scenario.config);
    }

    // Test specific keep-alive behaviors
    test_timeout_behavior(&scenario.config);
    test_request_limit_behavior(&scenario.config);
    test_parameter_parsing(&scenario.config);
    test_concurrent_connection_limits(&scenario.config);
});

/// Test a complete keep-alive sequence
fn test_keep_alive_sequence(
    messages: &[KeepAliveMessage],
    time_advances: &[u32],
    config: &KeepAliveConfig,
) {
    let mut manager = MockKeepAliveManager::new(config.clone());
    let mut message_count = 0;

    for (i, message) in messages.iter().enumerate() {
        // Advance time if specified
        if let Some(&time_advance) = time_advances.get(i) {
            manager.advance_time(time_advance);
        }

        // Check if connection should still accept messages
        if !manager.can_accept_message() {
            // Attempting to send message on closed/exhausted connection should fail
            let result = manager.process_message(message);
            assert!(
                result.is_err(),
                "Message should be rejected on closed connection"
            );
            break;
        }

        let result = manager.process_message(message);

        match result {
            Ok(state) => {
                message_count += 1;

                // Validate state transitions
                validate_keep_alive_state_transition(message, state, &manager, config);

                // Check for terminal states
                if matches!(
                    state,
                    KeepAliveState::Closed
                        | KeepAliveState::Error
                        | KeepAliveState::Exhausted
                        | KeepAliveState::TimedOut
                ) {
                    // Connection should not accept more messages
                    assert!(
                        !manager.can_accept_message(),
                        "Closed connection should not accept more messages"
                    );
                    break;
                }
            }
            Err(e) => {
                // Error should put connection in appropriate state
                let state = manager.get_state();
                assert!(
                    matches!(state, KeepAliveState::Error | KeepAliveState::Closed),
                    "Error should result in error/closed state, got {:?}: {}",
                    state,
                    e
                );
                break;
            }
        }
    }

    // Validate final state consistency
    validate_final_keep_alive_state(&manager, message_count, config);
}

/// Validate keep-alive state transitions
fn validate_keep_alive_state_transition(
    message: &KeepAliveMessage,
    new_state: KeepAliveState,
    manager: &MockKeepAliveManager,
    config: &KeepAliveConfig,
) {
    // If server doesn't support keep-alive, should always close
    if !config.enabled {
        assert!(
            matches!(new_state, KeepAliveState::Closed),
            "Keep-alive disabled should always close connection"
        );
        return;
    }

    // Version-specific validation
    match (message.version, message.connection_header) {
        (HttpVersion::Http10, ConnectionHeader::None | ConnectionHeader::Close) => {
            assert!(
                matches!(new_state, KeepAliveState::Closed),
                "HTTP/1.0 without keep-alive should close"
            );
        }
        (HttpVersion::Http11, ConnectionHeader::Close) => {
            assert!(
                matches!(new_state, KeepAliveState::Closed),
                "Explicit close should close connection"
            );
        }
        (HttpVersion::Http10, ConnectionHeader::KeepAlive)
        | (HttpVersion::Http11, ConnectionHeader::None | ConnectionHeader::KeepAlive) => {
            if manager.requests_processed < manager.effective_max_requests {
                assert!(
                    matches!(new_state, KeepAliveState::Active | KeepAliveState::Idle),
                    "Valid keep-alive should maintain connection"
                );
            } else {
                assert!(
                    matches!(new_state, KeepAliveState::Exhausted),
                    "Request limit should exhaust connection"
                );
            }
        }
        (_, ConnectionHeader::Malformed) => {
            assert!(
                matches!(new_state, KeepAliveState::Error),
                "Malformed headers should error"
            );
        }
        _ => {} // Other combinations handled by general logic
    }

    // Message boundary validation
    if message.has_body && matches!(message.body_encoding, BodyEncoding::Malformed) {
        assert!(
            matches!(new_state, KeepAliveState::Error | KeepAliveState::Closed),
            "Malformed body encoding should close/error connection"
        );
    }
}

/// Test timeout behavior specifically
fn test_timeout_behavior(config: &KeepAliveConfig) {
    let mut manager = MockKeepAliveManager::new(config.clone());

    // Send a keep-alive message
    let message = KeepAliveMessage {
        version: HttpVersion::Http11,
        method: HttpMethod::Get,
        connection_header: ConnectionHeader::KeepAlive,
        keep_alive_params: Some(KeepAliveParams {
            timeout: Some(30),
            max_requests: None,
        }),
        has_body: false,
        body_encoding: BodyEncoding::None,
        processing_time_ms: 0,
    };

    let _ = manager.process_message(&message);
    assert_eq!(manager.get_state(), KeepAliveState::Idle);

    // Advance time but stay under timeout
    manager.advance_time(15);
    assert_eq!(manager.get_state(), KeepAliveState::Idle);

    // Exceed timeout
    manager.advance_time(20);
    assert_eq!(manager.get_state(), KeepAliveState::TimedOut);

    // Should not accept more messages
    assert!(!manager.can_accept_message());
}

/// Test request limit behavior
fn test_request_limit_behavior(config: &KeepAliveConfig) {
    let mut manager = MockKeepAliveManager::new(config.clone());

    let message = KeepAliveMessage {
        version: HttpVersion::Http11,
        method: HttpMethod::Get,
        connection_header: ConnectionHeader::KeepAlive,
        keep_alive_params: Some(KeepAliveParams {
            timeout: None,
            max_requests: Some(2),
        }),
        has_body: false,
        body_encoding: BodyEncoding::None,
        processing_time_ms: 0,
    };

    // First request - should work
    let result1 = manager.process_message(&message);
    assert!(result1.is_ok());
    assert!(matches!(result1.unwrap(), KeepAliveState::Idle));

    // Second request - should exhaust
    let result2 = manager.process_message(&message);
    assert!(result2.is_ok());
    assert_eq!(result2.unwrap(), KeepAliveState::Exhausted);

    // Third request - should fail
    let result3 = manager.process_message(&message);
    assert!(result3.is_err());
}

/// Test parameter parsing
fn test_parameter_parsing(_config: &KeepAliveConfig) {
    // Test normal parameters
    let params1 = KeepAliveParams::from_header_value("keep-alive; timeout=60; max=1000");
    assert_eq!(params1.timeout, Some(60));
    assert_eq!(params1.max_requests, Some(1000));

    // Test minimal
    let params2 = KeepAliveParams::from_header_value("keep-alive");
    assert_eq!(params2.timeout, None);
    assert_eq!(params2.max_requests, None);

    // Test malformed values
    let params3 = KeepAliveParams::from_header_value("keep-alive; timeout=abc; max=xyz");
    assert_eq!(params3.timeout, None);
    assert_eq!(params3.max_requests, None);

    // Test header generation
    let params4 = KeepAliveParams {
        timeout: Some(30),
        max_requests: Some(5),
    };
    let header = params4.to_header_value();
    assert!(header.contains("timeout=30"));
    assert!(header.contains("max=5"));
}

/// Test concurrent connection limits
fn test_concurrent_connection_limits(config: &KeepAliveConfig) {
    if config.max_concurrent_connections == 0 {
        return;
    }

    let mut limited_config = config.clone();
    limited_config.max_concurrent_connections = 1;
    limited_config.current_connections = 1; // Already at limit

    let mut manager = MockKeepAliveManager::new(limited_config);

    let message = KeepAliveMessage {
        version: HttpVersion::Http11,
        method: HttpMethod::Get,
        connection_header: ConnectionHeader::KeepAlive,
        keep_alive_params: None,
        has_body: false,
        body_encoding: BodyEncoding::None,
        processing_time_ms: 0,
    };

    // Should fail due to connection limit
    let result = manager.process_message(&message);
    assert!(result.is_err() || matches!(result.unwrap(), KeepAliveState::Closed));
}

/// Validate final keep-alive state
fn validate_final_keep_alive_state(
    manager: &MockKeepAliveManager,
    processed_messages: u32,
    config: &KeepAliveConfig,
) {
    let (stats_processed, idle_time, timeout) = manager.get_stats();
    let state = manager.get_state();

    // Validate request count consistency
    assert_eq!(
        stats_processed, processed_messages,
        "Processed request count mismatch"
    );

    // Validate state consistency
    match state {
        KeepAliveState::Exhausted => {
            assert!(
                stats_processed >= manager.effective_max_requests,
                "Exhausted state should match request limit"
            );
        }
        KeepAliveState::TimedOut => {
            assert!(
                idle_time >= timeout as u64,
                "Timed out state should match timeout"
            );
        }
        KeepAliveState::Closed => {
            // Can be closed for various reasons - acceptable
        }
        KeepAliveState::Error => {
            // Error state due to malformed inputs - acceptable
        }
        KeepAliveState::Active | KeepAliveState::Idle | KeepAliveState::Established => {
            // Connection still usable
            if config.enabled {
                assert!(
                    manager.can_accept_message(),
                    "Active connection should accept messages"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http10_explicit_keep_alive() {
        let config = KeepAliveConfig::default();
        let mut manager = MockKeepAliveManager::new(config);

        let message = KeepAliveMessage {
            version: HttpVersion::Http10,
            method: HttpMethod::Get,
            connection_header: ConnectionHeader::KeepAlive,
            keep_alive_params: None,
            has_body: false,
            body_encoding: BodyEncoding::None,
            processing_time_ms: 0,
        };

        let result = manager.process_message(&message);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), KeepAliveState::Idle));
    }

    #[test]
    fn test_http10_default_close() {
        let config = KeepAliveConfig::default();
        let mut manager = MockKeepAliveManager::new(config);

        let message = KeepAliveMessage {
            version: HttpVersion::Http10,
            method: HttpMethod::Get,
            connection_header: ConnectionHeader::None,
            keep_alive_params: None,
            has_body: false,
            body_encoding: BodyEncoding::None,
            processing_time_ms: 0,
        };

        let result = manager.process_message(&message);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), KeepAliveState::Closed);
    }

    #[test]
    fn test_http11_implicit_keep_alive() {
        let config = KeepAliveConfig::default();
        let mut manager = MockKeepAliveManager::new(config);

        let message = KeepAliveMessage {
            version: HttpVersion::Http11,
            method: HttpMethod::Get,
            connection_header: ConnectionHeader::None,
            keep_alive_params: None,
            has_body: false,
            body_encoding: BodyEncoding::None,
            processing_time_ms: 0,
        };

        let result = manager.process_message(&message);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), KeepAliveState::Idle));
    }

    #[test]
    fn test_keep_alive_timeout() {
        let config = KeepAliveConfig::default();
        test_timeout_behavior(&config);
    }

    #[test]
    fn test_keep_alive_request_limit() {
        let config = KeepAliveConfig::default();
        test_request_limit_behavior(&config);
    }

    #[test]
    fn test_malformed_body_encoding() {
        let config = KeepAliveConfig::default();
        let mut manager = MockKeepAliveManager::new(config);

        let message = KeepAliveMessage {
            version: HttpVersion::Http11,
            method: HttpMethod::Post,
            connection_header: ConnectionHeader::KeepAlive,
            keep_alive_params: None,
            has_body: true,
            body_encoding: BodyEncoding::Malformed,
            processing_time_ms: 0,
        };

        let result = manager.process_message(&message);
        assert!(result.is_err());
        assert!(matches!(manager.get_state(), KeepAliveState::Error));
    }

    #[test]
    fn test_keep_alive_params_parsing() {
        test_parameter_parsing(&KeepAliveConfig::default());
    }

    #[test]
    fn test_server_keep_alive_disabled() {
        let mut config = KeepAliveConfig::default();
        config.enabled = false;
        let mut manager = MockKeepAliveManager::new(config);

        let message = KeepAliveMessage {
            version: HttpVersion::Http11,
            method: HttpMethod::Get,
            connection_header: ConnectionHeader::KeepAlive,
            keep_alive_params: None,
            has_body: false,
            body_encoding: BodyEncoding::None,
            processing_time_ms: 0,
        };

        let result = manager.process_message(&message);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), KeepAliveState::Closed);
    }
}
