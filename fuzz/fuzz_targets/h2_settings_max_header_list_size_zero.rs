#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::collections::HashMap;

/// HTTP/2 SETTINGS_MAX_HEADER_LIST_SIZE=0 fuzz target.
///
/// Tests edge case where peer sends SETTINGS_MAX_HEADER_LIST_SIZE=0, which
/// effectively forbids any HEADERS frames. This creates a paradox: HTTP/2
/// requires pseudo-headers (:method, :path, :scheme, :authority) but the
/// peer setting says "no headers allowed".
///
/// RFC 7540 §6.5.2: "This setting can be used to avoid fragmentation attacks
/// based on large header blocks." A value of 0 effectively forbids all headers.
///
/// Critical test questions:
/// - Must we reject ALL outgoing requests?
/// - How to handle required pseudo-headers?
/// - What error condition is appropriate?
/// - Must not panic on this edge case

#[derive(Arbitrary, Debug, Clone)]
struct SettingsZeroHeaderInput {
    /// Initial SETTINGS_MAX_HEADER_LIST_SIZE value
    initial_max_header_size: u32,

    /// New setting value (should be 0 for this test)
    new_max_header_size: u32,

    /// Request scenarios to test after setting
    request_scenarios: Vec<RequestScenario>,

    /// Connection state and configuration
    connection_config: ConnectionConfig,

    /// Validation policy
    policy: ZeroHeaderPolicy,
}

#[derive(Arbitrary, Debug, Clone)]
struct RequestScenario {
    /// Pseudo-headers required by HTTP/2
    pseudo_headers: PseudoHeaders,

    /// Regular headers
    regular_headers: Vec<HeaderPair>,

    /// Expected behavior after zero limit
    expected_behavior: ExpectedBehavior,
}

#[derive(Arbitrary, Debug, Clone)]
struct PseudoHeaders {
    method: String,
    path: String,
    scheme: String,
    authority: Option<String>,
}

impl Default for PseudoHeaders {
    fn default() -> Self {
        Self {
            method: "GET".to_string(),
            path: "/".to_string(),
            scheme: "https".to_string(),
            authority: Some("example.com".to_string()),
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
struct HeaderPair {
    name: String,
    value: String,
}

#[derive(Arbitrary, Debug, Clone)]
enum ExpectedBehavior {
    ShouldReject,
    ShouldAccept,
    ImplementationDefined,
}

#[derive(Arbitrary, Debug, Clone)]
struct ConnectionConfig {
    /// Whether this is client or server side
    is_client: bool,

    /// Initial connection window size
    initial_window_size: u32,

    /// Whether to enable PUSH_PROMISE
    enable_push: bool,

    /// Maximum concurrent streams
    max_concurrent_streams: u32,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            is_client: true,
            initial_window_size: 65535,
            enable_push: true,
            max_concurrent_streams: 100,
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
struct ZeroHeaderPolicy {
    /// How to handle zero header list size
    zero_size_handling: ZeroSizeHandling,

    /// Whether to allow minimal pseudo-headers only
    allow_minimal_pseudoheaders: bool,

    /// Whether to fail gracefully or return error
    fail_gracefully: bool,

    /// Maximum allowed header list size for comparison
    fallback_max_size: u32,
}

impl Default for ZeroHeaderPolicy {
    fn default() -> Self {
        Self {
            zero_size_handling: ZeroSizeHandling::RejectAllHeaders,
            allow_minimal_pseudoheaders: false,
            fail_gracefully: true,
            fallback_max_size: 8192,
        }
    }
}

#[derive(Arbitrary, Debug, Clone, PartialEq)]
enum ZeroSizeHandling {
    /// Reject all HEADERS frames
    RejectAllHeaders,
    /// Allow minimal pseudo-headers only
    AllowMinimalPseudo,
    /// Use implementation default
    UseDefault,
    /// Treat as connection error
    ConnectionError,
}

/// Mock HTTP/2 connection for testing SETTINGS_MAX_HEADER_LIST_SIZE=0
struct MockH2SettingsConnection {
    max_header_list_size: u32,
    config: ConnectionConfig,
    policy: ZeroHeaderPolicy,
    connection_active: bool,
}

impl MockH2SettingsConnection {
    fn new(config: ConnectionConfig, policy: ZeroHeaderPolicy) -> Self {
        Self {
            max_header_list_size: 8192, // RFC 7540 default (unspecified but common)
            config,
            policy,
            connection_active: true,
        }
    }

    /// Process SETTINGS frame with MAX_HEADER_LIST_SIZE
    fn process_settings(&mut self, max_header_list_size: u32) -> SettingsResult {
        // RFC 7540 §6.5.2: No specified lower bound, so 0 is technically valid
        let old_size = self.max_header_list_size;
        self.max_header_list_size = max_header_list_size;

        if max_header_list_size == 0 {
            return self.handle_zero_header_size(old_size);
        }

        SettingsResult::Updated {
            old_size,
            new_size: max_header_list_size,
            impact: if max_header_list_size < old_size {
                "Decreased header list size limit".to_string()
            } else {
                "Increased header list size limit".to_string()
            },
        }
    }

    fn handle_zero_header_size(&mut self, old_size: u32) -> SettingsResult {
        match self.policy.zero_size_handling {
            ZeroSizeHandling::RejectAllHeaders => {
                SettingsResult::ZeroSizePolicy {
                    policy: "Reject all HEADERS frames".to_string(),
                    pseudo_headers_allowed: false,
                    connection_usable: false,
                }
            },

            ZeroSizeHandling::AllowMinimalPseudo => {
                SettingsResult::ZeroSizePolicy {
                    policy: "Allow minimal pseudo-headers only".to_string(),
                    pseudo_headers_allowed: true,
                    connection_usable: true,
                }
            },

            ZeroSizeHandling::UseDefault => {
                // Fallback to reasonable default
                self.max_header_list_size = self.policy.fallback_max_size;
                SettingsResult::Updated {
                    old_size,
                    new_size: self.policy.fallback_max_size,
                    impact: "Used fallback size due to zero setting".to_string(),
                }
            },

            ZeroSizeHandling::ConnectionError => {
                self.connection_active = false;
                SettingsResult::ConnectionError(
                    "SETTINGS_MAX_HEADER_LIST_SIZE=0 treated as connection error".to_string()
                )
            }
        }
    }

    /// Attempt to send HEADERS frame and validate against current limit
    fn send_headers(&self, scenario: &RequestScenario) -> HeadersSendResult {
        if !self.connection_active {
            return HeadersSendResult::ConnectionClosed(
                "Connection closed due to settings".to_string()
            );
        }

        let header_size = self.calculate_header_size(scenario);

        if self.max_header_list_size == 0 {
            return self.handle_zero_size_headers(scenario, header_size);
        }

        if header_size > self.max_header_list_size as usize {
            return HeadersSendResult::Rejected(
                format!("Headers size {} exceeds limit {}", header_size, self.max_header_list_size)
            );
        }

        HeadersSendResult::Sent {
            header_count: self.count_headers(scenario),
            total_size: header_size,
            within_limit: true,
        }
    }

    fn handle_zero_size_headers(&self, scenario: &RequestScenario, header_size: usize) -> HeadersSendResult {
        match self.policy.zero_size_handling {
            ZeroSizeHandling::RejectAllHeaders => {
                HeadersSendResult::Rejected(
                    "All headers rejected due to SETTINGS_MAX_HEADER_LIST_SIZE=0".to_string()
                )
            },

            ZeroSizeHandling::AllowMinimalPseudo if self.policy.allow_minimal_pseudoheaders => {
                // Only allow essential pseudo-headers
                if scenario.regular_headers.is_empty() && self.is_minimal_pseudo_headers(&scenario.pseudo_headers) {
                    HeadersSendResult::Sent {
                        header_count: 4, // :method, :path, :scheme, :authority
                        total_size: self.calculate_pseudo_header_size(&scenario.pseudo_headers),
                        within_limit: false, // Technically exceeds 0, but allowed by policy
                    }
                } else {
                    HeadersSendResult::Rejected(
                        "Only minimal pseudo-headers allowed with zero limit".to_string()
                    )
                }
            },

            ZeroSizeHandling::UseDefault => {
                // Use fallback limit
                if header_size > self.policy.fallback_max_size as usize {
                    HeadersSendResult::Rejected(
                        format!("Headers exceed fallback limit {}", self.policy.fallback_max_size)
                    )
                } else {
                    HeadersSendResult::Sent {
                        header_count: self.count_headers(scenario),
                        total_size: header_size,
                        within_limit: true,
                    }
                }
            },

            _ => HeadersSendResult::Rejected(
                "Headers rejected due to zero size policy".to_string()
            )
        }
    }

    fn calculate_header_size(&self, scenario: &RequestScenario) -> usize {
        let mut size = 0;

        // Pseudo-headers (RFC 7540 §8.1.2)
        size += self.calculate_pseudo_header_size(&scenario.pseudo_headers);

        // Regular headers
        for header in &scenario.regular_headers {
            size += header.name.len() + header.value.len() + 32; // HPACK overhead estimate
        }

        size
    }

    fn calculate_pseudo_header_size(&self, pseudo: &PseudoHeaders) -> usize {
        let mut size = 0;
        size += 7 + pseudo.method.len(); // ":method" + value
        size += 5 + pseudo.path.len();   // ":path" + value
        size += 7 + pseudo.scheme.len(); // ":scheme" + value
        if let Some(ref authority) = pseudo.authority {
            size += 10 + authority.len(); // ":authority" + value
        }
        size + 64 // HPACK encoding overhead estimate
    }

    fn count_headers(&self, scenario: &RequestScenario) -> usize {
        let mut count = 3; // :method, :path, :scheme
        if scenario.pseudo_headers.authority.is_some() {
            count += 1; // :authority
        }
        count += scenario.regular_headers.len();
        count
    }

    fn is_minimal_pseudo_headers(&self, pseudo: &PseudoHeaders) -> bool {
        // Check if these are truly minimal required headers
        pseudo.method == "GET" &&
        pseudo.path == "/" &&
        (pseudo.scheme == "http" || pseudo.scheme == "https") &&
        pseudo.authority.is_some()
    }
}

#[derive(Debug, PartialEq)]
enum SettingsResult {
    /// Settings updated successfully
    Updated {
        old_size: u32,
        new_size: u32,
        impact: String,
    },

    /// Zero size requires special policy
    ZeroSizePolicy {
        policy: String,
        pseudo_headers_allowed: bool,
        connection_usable: bool,
    },

    /// Connection error due to settings
    ConnectionError(String),
}

#[derive(Debug, PartialEq)]
enum HeadersSendResult {
    /// Headers sent successfully
    Sent {
        header_count: usize,
        total_size: usize,
        within_limit: bool,
    },

    /// Headers rejected due to size limit
    Rejected(String),

    /// Connection is closed
    ConnectionClosed(String),
}

fuzz_target!(|input: SettingsZeroHeaderInput| {
    // Normalize input for reasonable fuzzing
    let mut input = input;
    if input.new_max_header_size > 1000000 {
        input.new_max_header_size = 0; // Focus on zero case
    }

    let mut connection = MockH2SettingsConnection::new(
        input.connection_config.clone(),
        input.policy.clone()
    );

    // Process initial settings update
    let settings_result = connection.process_settings(input.new_max_header_size);

    // Test settings processing doesn't panic
    match settings_result {
        SettingsResult::ZeroSizePolicy { connection_usable, pseudo_headers_allowed, .. } => {
            // Verify zero size handling is reasonable
            if input.new_max_header_size == 0 {
                match input.policy.zero_size_handling {
                    ZeroSizeHandling::RejectAllHeaders => {
                        assert!(!connection_usable, "Connection should be unusable with reject-all policy");
                        assert!(!pseudo_headers_allowed, "Pseudo headers should not be allowed");
                    },
                    ZeroSizeHandling::AllowMinimalPseudo => {
                        assert!(connection_usable || pseudo_headers_allowed,
                               "Should allow some functionality with minimal pseudo policy");
                    },
                    ZeroSizeHandling::ConnectionError => {
                        // Connection error is acceptable response to zero setting
                    },
                    _ => {}
                }
            }
        },

        SettingsResult::Updated { new_size, .. } => {
            assert_eq!(new_size, connection.max_header_list_size,
                      "Connection should reflect new header size");
        },

        SettingsResult::ConnectionError(_) => {
            assert!(!connection.connection_active,
                   "Connection should be inactive after connection error");
        }
    }

    // Test header sending scenarios
    for scenario in input.request_scenarios.iter().take(3) { // Limit for performance
        let headers_result = connection.send_headers(scenario);

        match headers_result {
            HeadersSendResult::Sent { header_count, total_size, within_limit } => {
                // Verify sent headers are reasonable
                assert!(header_count > 0, "Should have at least some headers");

                if input.new_max_header_size == 0 && within_limit {
                    // Should only happen with special policies
                    match input.policy.zero_size_handling {
                        ZeroSizeHandling::AllowMinimalPseudo | ZeroSizeHandling::UseDefault => {
                            // Acceptable
                        },
                        _ => {
                            panic!("Headers should not be within zero limit unless policy allows it");
                        }
                    }
                }

                if input.new_max_header_size > 0 && total_size > input.new_max_header_size as usize {
                    panic!("Headers {} should not exceed limit {}", total_size, input.new_max_header_size);
                }
            },

            HeadersSendResult::Rejected(ref reason) => {
                // Verify rejection is reasonable
                if input.new_max_header_size == 0 {
                    assert!(reason.contains("zero") || reason.contains("rejected") || reason.contains("limit"),
                           "Zero size rejection should mention the limit: {}", reason);
                }
            },

            HeadersSendResult::ConnectionClosed(ref reason) => {
                // Connection closure should be explainable
                assert!(reason.contains("closed") || reason.contains("settings"),
                       "Connection closure should explain reason: {}", reason);
            }
        }
    }

    // Additional edge case validation
    if input.new_max_header_size == 0 {
        // Test that connection handles minimal required headers appropriately
        let minimal_scenario = RequestScenario {
            pseudo_headers: PseudoHeaders::default(),
            regular_headers: Vec::new(),
            expected_behavior: ExpectedBehavior::ImplementationDefined,
        };

        let minimal_result = connection.send_headers(&minimal_scenario);

        match minimal_result {
            HeadersSendResult::Sent { .. } => {
                // Only acceptable with permissive policies
                assert!(matches!(input.policy.zero_size_handling,
                               ZeroSizeHandling::AllowMinimalPseudo | ZeroSizeHandling::UseDefault),
                       "Minimal headers should only be sent with permissive policies");
            },
            HeadersSendResult::Rejected(_) => {
                // Acceptable - zero means zero
            },
            HeadersSendResult::ConnectionClosed(_) => {
                // Acceptable - connection became unusable
            }
        }
    }

    // Verify no panics occurred during processing
    // (Implicit - if we reach here without panicking, the test passed)
});