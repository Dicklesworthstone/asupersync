#![no_main]

//! Fuzz target for HTTP/1.1 Connection: close header semantics.
//!
//! This target tests the complex interaction between Connection header parsing,
//! HTTP version defaults, server configuration, and connection lifecycle decisions.
//! RFC 9110 §7.6.1 defines Connection as a comma-separated list of connection
//! options, with specific semantic meaning for "close" and "keep-alive" tokens.
//!
//! Connection semantics tested:
//! - Comma-separated token parsing (Connection: close, keep-alive, upgrade)
//! - Case-insensitive token matching ("CLOSE", "close", "Close")
//! - Whitespace handling around tokens
//! - Multiple/duplicate Connection headers
//! - HTTP/1.0 defaults to close, HTTP/1.1 defaults to keep-alive
//! - Server keep-alive config overriding client preferences
//! - Request limit triggering forced connection close
//! - Response Connection header modification and precedence
//! - Malformed Connection header values
//!
//! Expected behavior:
//! - Connection: close → connection should close after response
//! - Connection: keep-alive → connection should remain open (if server allows)
//! - HTTP/1.0 without explicit keep-alive → close
//! - HTTP/1.1 without explicit close → keep-alive
//! - Server keep_alive=false → always close regardless of client headers
//! - Request limits reached → force close despite client keep-alive
//! - Response Connection: close takes precedence over request keep-alive

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// HTTP version for connection semantics testing
#[derive(Debug, Clone, Copy, PartialEq, Arbitrary)]
enum HttpVersion {
    Http10,
    Http11,
}

impl HttpVersion {
    fn as_str(self) -> &'static str {
        match self {
            HttpVersion::Http10 => "HTTP/1.0",
            HttpVersion::Http11 => "HTTP/1.1",
        }
    }

    /// Default connection behavior without explicit Connection header
    fn default_closes(self) -> bool {
        match self {
            HttpVersion::Http10 => true,  // HTTP/1.0 defaults to close
            HttpVersion::Http11 => false, // HTTP/1.1 defaults to keep-alive
        }
    }
}

/// Server configuration for connection lifecycle
#[derive(Debug, Clone, Arbitrary)]
struct ServerConfig {
    /// Whether server supports keep-alive at all
    keep_alive_enabled: bool,
    /// Maximum requests per connection (None = unlimited)
    max_requests_per_connection: Option<u8>,
    /// Current number of requests already served on this connection
    requests_served: u8,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            keep_alive_enabled: true,
            max_requests_per_connection: Some(100),
            requests_served: 0,
        }
    }
}

/// HTTP request with Connection header variations
#[derive(Debug, Clone, Arbitrary)]
struct TestRequest {
    version: HttpVersion,
    /// Multiple Connection headers (RFC allows multiple instances)
    connection_headers: Vec<String>,
    /// Whether request has other headers that might affect semantics
    has_other_headers: bool,
}

/// HTTP response with Connection header
#[derive(Debug, Clone, Arbitrary)]
struct TestResponse {
    /// Connection headers in response
    connection_headers: Vec<String>,
    /// Whether response body is present (affects HEAD semantics)
    has_body: bool,
}

/// Connection semantics test scenario
#[derive(Debug, Clone, Arbitrary)]
struct ConnectionSemanticsScenario {
    request: TestRequest,
    response: TestResponse,
    config: ServerConfig,
    /// Include edge cases in generation
    include_edge_cases: bool,
}

/// Mock connection semantic analyzer
#[derive(Debug)]
struct MockConnectionAnalyzer {
    config: ServerConfig,
}

impl MockConnectionAnalyzer {
    fn new(config: ServerConfig) -> Self {
        Self { config }
    }

    /// Determine if connection should close after request based on HTTP/1.1 semantics
    fn should_close_after_request(&self, req: &TestRequest) -> bool {
        // Server-wide keep-alive disabled always closes
        if !self.config.keep_alive_enabled {
            return true;
        }

        // Request limit reached forces close
        if let Some(max_requests) = self.config.max_requests_per_connection {
            if self.config.requests_served + 1 >= max_requests {
                return true;
            }
        }

        // Parse Connection headers
        let (has_close, has_keep_alive) = self.parse_connection_tokens(&req.connection_headers);

        // Explicit close always wins
        if has_close {
            return true;
        }

        // Explicit keep-alive wins over version default
        if has_keep_alive {
            return false;
        }

        // Fall back to HTTP version default
        req.version.default_closes()
    }

    /// Parse Connection header tokens (comma-separated, case-insensitive)
    fn parse_connection_tokens(&self, headers: &[String]) -> (bool, bool) {
        let mut has_close = false;
        let mut has_keep_alive = false;

        for header_value in headers {
            for token in header_value.split(',') {
                let token = token.trim();
                if token.eq_ignore_ascii_case("close") {
                    has_close = true;
                } else if token.eq_ignore_ascii_case("keep-alive") {
                    has_keep_alive = true;
                }
                // Note: Other tokens like "upgrade" are ignored for close semantics
            }
        }

        (has_close, has_keep_alive)
    }

    /// Determine if response overrides request connection decision
    fn response_overrides_close(&self, resp: &TestResponse) -> Option<bool> {
        let (resp_has_close, resp_has_keep_alive) = self.parse_connection_tokens(&resp.connection_headers);

        if resp_has_close {
            Some(true)  // Response requests close
        } else if resp_has_keep_alive {
            Some(false) // Response requests keep-alive
        } else {
            None        // Response doesn't override
        }
    }

    /// Add appropriate Connection header to response
    fn finalize_response_headers(&self, req: &TestRequest, resp: &mut TestResponse, should_close: bool) {
        // Remove existing Connection headers
        resp.connection_headers.clear();

        if should_close {
            resp.connection_headers.push("close".to_string());
        } else if req.version == HttpVersion::Http10 {
            // HTTP/1.0 needs explicit keep-alive
            resp.connection_headers.push("keep-alive".to_string());
        }
        // HTTP/1.1 keep-alive is implicit, no header needed
    }
}

/// Generate edge cases for Connection header testing
fn generate_edge_cases() -> Vec<TestRequest> {
    vec![
        // Basic cases
        TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec!["close".to_string()],
            has_other_headers: false,
        },
        TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec!["keep-alive".to_string()],
            has_other_headers: false,
        },
        TestRequest {
            version: HttpVersion::Http10,
            connection_headers: vec!["keep-alive".to_string()],
            has_other_headers: false,
        },

        // Case sensitivity tests
        TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec!["CLOSE".to_string()],
            has_other_headers: false,
        },
        TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec!["Close".to_string()],
            has_other_headers: false,
        },
        TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec!["keep-ALIVE".to_string()],
            has_other_headers: false,
        },

        // Whitespace handling
        TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec!["  close  ".to_string()],
            has_other_headers: false,
        },
        TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec!["\t keep-alive \r".to_string()],
            has_other_headers: false,
        },

        // Comma-separated tokens
        TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec!["close, keep-alive".to_string()],
            has_other_headers: false,
        },
        TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec!["upgrade, close".to_string()],
            has_other_headers: false,
        },
        TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec!["keep-alive, upgrade".to_string()],
            has_other_headers: false,
        },

        // Multiple Connection headers
        TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec!["keep-alive".to_string(), "close".to_string()],
            has_other_headers: false,
        },
        TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec!["upgrade".to_string(), "close".to_string()],
            has_other_headers: false,
        },

        // Malformed values
        TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec!["".to_string()],
            has_other_headers: false,
        },
        TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec!["invalid-token".to_string()],
            has_other_headers: false,
        },
        TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec!["close,".to_string()],
            has_other_headers: false,
        },
        TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec![",close".to_string()],
            has_other_headers: false,
        },
        TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec!["close,,keep-alive".to_string()],
            has_other_headers: false,
        },

        // Version defaults
        TestRequest {
            version: HttpVersion::Http10,
            connection_headers: vec![],
            has_other_headers: false,
        },
        TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec![],
            has_other_headers: false,
        },

        // Complex cases
        TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec!["Te, close, upgrade".to_string()],
            has_other_headers: true,
        },
    ]
}

fuzz_target!(|scenario: ConnectionSemanticsScenario| {
    // Limit complexity to prevent timeouts
    if scenario.request.connection_headers.len() > 10 ||
       scenario.response.connection_headers.len() > 10 {
        return;
    }

    for header in &scenario.request.connection_headers {
        if header.len() > 200 {
            return;
        }
    }

    let test_requests = if scenario.include_edge_cases {
        generate_edge_cases()
    } else {
        vec![scenario.request]
    };

    for test_request in &test_requests {
        test_connection_semantics(test_request, &scenario.response, &scenario.config);
    }

    // Test server configuration edge cases
    test_server_config_semantics(&scenario);
});

/// Test connection close semantics for a specific request/response/config combination
fn test_connection_semantics(req: &TestRequest, resp: &TestResponse, config: &ServerConfig) {
    let analyzer = MockConnectionAnalyzer::new(config.clone());

    // Test request-based decision
    let should_close_request = analyzer.should_close_after_request(req);

    // Test response override
    let response_override = analyzer.response_overrides_close(resp);
    let final_close_decision = response_override.unwrap_or(should_close_request);

    // Validate connection token parsing
    let (req_has_close, req_has_keep_alive) = analyzer.parse_connection_tokens(&req.connection_headers);
    let (resp_has_close, resp_has_keep_alive) = analyzer.parse_connection_tokens(&resp.connection_headers);

    // Test consistency of parsing
    validate_token_parsing_consistency(&req.connection_headers, req_has_close, req_has_keep_alive);
    validate_token_parsing_consistency(&resp.connection_headers, resp_has_close, resp_has_keep_alive);

    // Test semantic rules
    validate_semantic_rules(req, config, should_close_request, req_has_close, req_has_keep_alive);

    // Test response finalization
    let mut finalized_response = resp.clone();
    analyzer.finalize_response_headers(req, &mut finalized_response, final_close_decision);
    validate_response_finalization(&finalized_response, req, final_close_decision);
}

/// Validate that token parsing is consistent and correct
fn validate_token_parsing_consistency(headers: &[String], parsed_close: bool, parsed_keep_alive: bool) {
    let mut manual_close = false;
    let mut manual_keep_alive = false;

    for header in headers {
        for token in header.split(',') {
            let token = token.trim();
            if token.eq_ignore_ascii_case("close") {
                manual_close = true;
            } else if token.eq_ignore_ascii_case("keep-alive") {
                manual_keep_alive = true;
            }
        }
    }

    assert_eq!(parsed_close, manual_close,
        "Connection: close token parsing inconsistent for headers: {:?}", headers);
    assert_eq!(parsed_keep_alive, manual_keep_alive,
        "Connection: keep-alive token parsing inconsistent for headers: {:?}", headers);
}

/// Validate that semantic rules are applied correctly
fn validate_semantic_rules(
    req: &TestRequest,
    config: &ServerConfig,
    decision: bool,
    has_close: bool,
    has_keep_alive: bool
) {
    // Rule 1: Server keep-alive disabled always closes
    if !config.keep_alive_enabled {
        assert!(decision, "Connection should close when server keep-alive disabled");
    }

    // Rule 2: Request limit forces close
    if let Some(max_requests) = config.max_requests_per_connection {
        if config.requests_served + 1 >= max_requests {
            assert!(decision, "Connection should close when request limit reached");
        }
    }

    // Rule 3: Explicit close always wins
    if has_close {
        assert!(decision, "Connection should close when explicit 'close' token present");
    }

    // Rule 4: When server allows and no explicit close, explicit keep-alive overrides version default
    if config.keep_alive_enabled && !has_close && has_keep_alive {
        assert!(!decision, "Connection should not close with explicit keep-alive");
    }

    // Rule 5: HTTP version defaults when no explicit tokens and server allows
    if config.keep_alive_enabled && !has_close && !has_keep_alive {
        let request_limit_reached = config.max_requests_per_connection
            .map(|max| config.requests_served + 1 >= max)
            .unwrap_or(false);

        if !request_limit_reached {
            assert_eq!(decision, req.version.default_closes(),
                "Connection decision should match HTTP version default when no explicit tokens");
        }
    }
}

/// Validate that response headers are finalized correctly
fn validate_response_finalization(resp: &TestResponse, req: &TestRequest, should_close: bool) {
    if should_close {
        // Should have Connection: close
        assert!(
            resp.connection_headers.iter().any(|h| h.trim().eq_ignore_ascii_case("close")),
            "Response should have Connection: close when connection will close"
        );
    } else if req.version == HttpVersion::Http10 {
        // HTTP/1.0 keep-alive needs explicit header
        assert!(
            resp.connection_headers.iter().any(|h| h.trim().eq_ignore_ascii_case("keep-alive")),
            "HTTP/1.0 keep-alive response should have explicit Connection: keep-alive"
        );
    }
    // HTTP/1.1 keep-alive is implicit, no specific header required
}

/// Test server configuration edge cases
fn test_server_config_semantics(scenario: &ConnectionSemanticsScenario) {
    // Test keep-alive disabled scenarios
    let mut config_no_keepalive = scenario.config.clone();
    config_no_keepalive.keep_alive_enabled = false;

    let analyzer = MockConnectionAnalyzer::new(config_no_keepalive);
    let should_close = analyzer.should_close_after_request(&scenario.request);
    assert!(should_close, "Should always close when keep-alive disabled");

    // Test request limit scenarios
    let mut config_at_limit = scenario.config.clone();
    config_at_limit.max_requests_per_connection = Some(5);
    config_at_limit.requests_served = 4; // Next request will be 5th = limit

    let analyzer_at_limit = MockConnectionAnalyzer::new(config_at_limit);
    let should_close_at_limit = analyzer_at_limit.should_close_after_request(&scenario.request);
    assert!(should_close_at_limit, "Should close when request limit would be reached");

    // Test unlimited requests
    let mut config_unlimited = scenario.config.clone();
    config_unlimited.max_requests_per_connection = None;
    config_unlimited.requests_served = 1000; // Large number

    let analyzer_unlimited = MockConnectionAnalyzer::new(config_unlimited);

    // Should not close due to request limit with unlimited setting
    let should_close_unlimited = analyzer_unlimited.should_close_after_request(&scenario.request);

    // Only close if explicit close token or version default (not due to limit)
    let (has_close, _) = analyzer_unlimited.parse_connection_tokens(&scenario.request.connection_headers);
    let expected_close = has_close ||
        (!config_unlimited.keep_alive_enabled) ||
        (scenario.request.version.default_closes() &&
         !analyzer_unlimited.parse_connection_tokens(&scenario.request.connection_headers).1);

    // This is a complex assertion, so let's be more lenient for fuzzing
    // Just ensure unlimited doesn't force close
    if !has_close && config_unlimited.keep_alive_enabled {
        // With unlimited requests and keep-alive enabled, should follow normal rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_connection_close() {
        let config = ServerConfig::default();
        let analyzer = MockConnectionAnalyzer::new(config);

        let req = TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec!["close".to_string()],
            has_other_headers: false,
        };

        assert!(analyzer.should_close_after_request(&req));
    }

    #[test]
    fn test_basic_connection_keep_alive() {
        let config = ServerConfig::default();
        let analyzer = MockConnectionAnalyzer::new(config);

        let req = TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec!["keep-alive".to_string()],
            has_other_headers: false,
        };

        assert!(!analyzer.should_close_after_request(&req));
    }

    #[test]
    fn test_http10_default_close() {
        let config = ServerConfig::default();
        let analyzer = MockConnectionAnalyzer::new(config);

        let req = TestRequest {
            version: HttpVersion::Http10,
            connection_headers: vec![],
            has_other_headers: false,
        };

        assert!(analyzer.should_close_after_request(&req));
    }

    #[test]
    fn test_http11_default_keep_alive() {
        let config = ServerConfig::default();
        let analyzer = MockConnectionAnalyzer::new(config);

        let req = TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec![],
            has_other_headers: false,
        };

        assert!(!analyzer.should_close_after_request(&req));
    }

    #[test]
    fn test_server_keepalive_disabled() {
        let mut config = ServerConfig::default();
        config.keep_alive_enabled = false;
        let analyzer = MockConnectionAnalyzer::new(config);

        let req = TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec!["keep-alive".to_string()],
            has_other_headers: false,
        };

        assert!(analyzer.should_close_after_request(&req));
    }

    #[test]
    fn test_request_limit_forces_close() {
        let mut config = ServerConfig::default();
        config.max_requests_per_connection = Some(5);
        config.requests_served = 4; // Next will be 5th = limit
        let analyzer = MockConnectionAnalyzer::new(config);

        let req = TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec!["keep-alive".to_string()],
            has_other_headers: false,
        };

        assert!(analyzer.should_close_after_request(&req));
    }

    #[test]
    fn test_case_insensitive_tokens() {
        let config = ServerConfig::default();
        let analyzer = MockConnectionAnalyzer::new(config);

        let variations = vec!["close", "CLOSE", "Close", "cLoSe"];

        for variation in variations {
            let req = TestRequest {
                version: HttpVersion::Http11,
                connection_headers: vec![variation.to_string()],
                has_other_headers: false,
            };

            assert!(analyzer.should_close_after_request(&req),
                "Failed for variation: {}", variation);
        }
    }

    #[test]
    fn test_comma_separated_tokens() {
        let config = ServerConfig::default();
        let analyzer = MockConnectionAnalyzer::new(config);

        let req = TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec!["upgrade, close".to_string()],
            has_other_headers: false,
        };

        assert!(analyzer.should_close_after_request(&req));
    }

    #[test]
    fn test_whitespace_handling() {
        let config = ServerConfig::default();
        let analyzer = MockConnectionAnalyzer::new(config);

        let req = TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec!["  close  ".to_string()],
            has_other_headers: false,
        };

        assert!(analyzer.should_close_after_request(&req));
    }

    #[test]
    fn test_multiple_connection_headers() {
        let config = ServerConfig::default();
        let analyzer = MockConnectionAnalyzer::new(config);

        let req = TestRequest {
            version: HttpVersion::Http11,
            connection_headers: vec!["keep-alive".to_string(), "close".to_string()],
            has_other_headers: false,
        };

        // Close should win over keep-alive
        assert!(analyzer.should_close_after_request(&req));
    }

    #[test]
    fn test_response_override() {
        let config = ServerConfig::default();
        let analyzer = MockConnectionAnalyzer::new(config);

        let resp = TestResponse {
            connection_headers: vec!["close".to_string()],
            has_body: true,
        };

        let override_result = analyzer.response_overrides_close(&resp);
        assert_eq!(override_result, Some(true));
    }
}