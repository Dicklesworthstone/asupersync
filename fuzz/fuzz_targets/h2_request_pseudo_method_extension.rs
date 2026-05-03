#![no_main]
//! HTTP/2 :method pseudo-header extension method fuzz target
//!
//! Tests handling of :method pseudo-headers with extension/custom methods
//! beyond the standard ones. Per RFC 9110 §9.1, HTTP methods are extensible
//! and implementations should accept unknown but well-formed method names.
//! Valid method names must be tokens (no whitespace, no control characters).
//!
//! Primary test scenario: Custom methods like "PROPFIND", "REPORT", "MKCOL"
//!
//! Test scenarios:
//! - WebDAV extension methods ("PROPFIND", "REPORT", "MKCOL", "MOVE", "COPY")
//! - Custom application methods ("BREW", "COFFEE", "TEAPOT")
//! - Methods with numbers ("HTTP2", "VERSION1", "API3")
//! - Long method names (testing parser limits)
//! - Invalid methods with whitespace ("GET POST", "METHOD NAME")
//! - Invalid methods with control chars ("METHOD\n", "METHOD\r", "METHOD\t")
//! - Invalid lowercase methods ("get", "post", "custom")
//! - Invalid methods with special chars ("METHOD!", "METHOD@", "METHOD:")
//! - Empty method names
//! - Boundary cases (single char, very long)
//!
//! RFC references:
//! - RFC 9110 §9.1: Method extensibility and token format
//! - RFC 9110 §5.6.2: Token syntax definition
//! - RFC 4918: WebDAV extension methods
//! - RFC 7540 §8.1.2.3: :method pseudo-header requirements

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Configuration for extension method testing
#[derive(Debug, Clone)]
struct ExtensionMethodTestConfig {
    /// Include well-known extension methods (WebDAV, etc.)
    pub include_webdav_methods: bool,
    /// Include custom application methods
    pub include_custom_methods: bool,
    /// Include methods with numbers
    pub include_numeric_methods: bool,
    /// Include invalid methods (for negative testing)
    pub include_invalid_methods: bool,
    /// Include very long method names
    pub include_long_methods: bool,
}

impl Default for ExtensionMethodTestConfig {
    fn default() -> Self {
        Self {
            include_webdav_methods: true,
            include_custom_methods: true,
            include_numeric_methods: true,
            include_invalid_methods: true,
            include_long_methods: true,
        }
    }
}

/// Mock HTTP/2 connection for extension method validation testing
#[derive(Debug)]
struct MockExtensionMethodConnection {
    /// Count of requests with well-known extension methods
    pub webdav_methods: Arc<Mutex<u64>>,
    /// Count of requests with custom application methods
    pub custom_methods: Arc<Mutex<u64>>,
    /// Count of requests with methods containing numbers
    pub numeric_methods: Arc<Mutex<u64>>,
    /// Count of requests with very long method names
    pub long_methods: Arc<Mutex<u64>>,
    /// Count of requests with single-character methods
    pub single_char_methods: Arc<Mutex<u64>>,
    /// Count of requests with invalid methods (whitespace)
    pub whitespace_methods: Arc<Mutex<u64>>,
    /// Count of requests with invalid methods (control characters)
    pub control_char_methods: Arc<Mutex<u64>>,
    /// Count of requests with lowercase methods
    pub lowercase_methods: Arc<Mutex<u64>>,
    /// Count of requests with special character methods
    pub special_char_methods: Arc<Mutex<u64>>,
    /// Count of requests with empty method names
    pub empty_methods: Arc<Mutex<u64>>,
    /// Count of accepted extension methods
    pub accepted_extensions: Arc<Mutex<u64>>,
    /// Count of rejected invalid methods
    pub rejected_methods: Arc<Mutex<u64>>,
    /// Count of standard methods (for comparison)
    pub standard_methods: Arc<Mutex<u64>>,
    /// Track consistency violations
    pub consistency_violations: Arc<Mutex<u64>>,
    /// Configuration for this test session
    pub config: ExtensionMethodTestConfig,
    /// Cache of previous decisions for consistency checking
    pub decision_cache: Arc<Mutex<HashMap<String, ExtensionMethodResult>>>,
}

impl MockExtensionMethodConnection {
    fn new(config: ExtensionMethodTestConfig) -> Self {
        Self {
            webdav_methods: Arc::new(Mutex::new(0)),
            custom_methods: Arc::new(Mutex::new(0)),
            numeric_methods: Arc::new(Mutex::new(0)),
            long_methods: Arc::new(Mutex::new(0)),
            single_char_methods: Arc::new(Mutex::new(0)),
            whitespace_methods: Arc::new(Mutex::new(0)),
            control_char_methods: Arc::new(Mutex::new(0)),
            lowercase_methods: Arc::new(Mutex::new(0)),
            special_char_methods: Arc::new(Mutex::new(0)),
            empty_methods: Arc::new(Mutex::new(0)),
            accepted_extensions: Arc::new(Mutex::new(0)),
            rejected_methods: Arc::new(Mutex::new(0)),
            standard_methods: Arc::new(Mutex::new(0)),
            consistency_violations: Arc::new(Mutex::new(0)),
            config,
            decision_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Process HTTP/2 request with :method extension validation
    fn handle_extension_method_request(&self, method: &str) -> ExtensionMethodResult {
        let analysis = self.analyze_method(method);

        // Track various method types
        if analysis.is_webdav_method {
            *self.webdav_methods.lock().unwrap() += 1;
        }

        if analysis.is_custom_method {
            *self.custom_methods.lock().unwrap() += 1;
        }

        if analysis.has_numbers {
            *self.numeric_methods.lock().unwrap() += 1;
        }

        if analysis.is_long_method {
            *self.long_methods.lock().unwrap() += 1;
        }

        if analysis.is_single_char {
            *self.single_char_methods.lock().unwrap() += 1;
        }

        if analysis.has_whitespace {
            *self.whitespace_methods.lock().unwrap() += 1;
        }

        if analysis.has_control_chars {
            *self.control_char_methods.lock().unwrap() += 1;
        }

        if analysis.has_lowercase {
            *self.lowercase_methods.lock().unwrap() += 1;
        }

        if analysis.has_special_chars {
            *self.special_char_methods.lock().unwrap() += 1;
        }

        if analysis.is_empty {
            *self.empty_methods.lock().unwrap() += 1;
        }

        if analysis.is_standard_method {
            *self.standard_methods.lock().unwrap() += 1;
        }

        // Determine if method is valid per RFC 9110
        let is_valid_method = self.validate_method_format(method, &analysis);

        // Check consistency with previous decisions
        let mut cache = self.decision_cache.lock().unwrap();
        let result = if is_valid_method {
            if analysis.is_standard_method {
                // Standard methods are always accepted
                ExtensionMethodResult::Accepted
            } else {
                // Valid extension method
                *self.accepted_extensions.lock().unwrap() += 1;
                ExtensionMethodResult::Accepted
            }
        } else {
            *self.rejected_methods.lock().unwrap() += 1;

            // Determine specific error reason
            if analysis.is_empty {
                ExtensionMethodResult::BadRequest("Empty method name")
            } else if analysis.has_whitespace {
                ExtensionMethodResult::BadRequest("Method contains whitespace")
            } else if analysis.has_control_chars {
                ExtensionMethodResult::BadRequest("Method contains control characters")
            } else if analysis.has_special_chars {
                ExtensionMethodResult::BadRequest("Method contains invalid characters")
            } else {
                ExtensionMethodResult::BadRequest("Invalid method format")
            }
        };

        // Consistency check
        if let Some(previous_result) = cache.get(method) {
            if !self.results_match(&result, previous_result) {
                *self.consistency_violations.lock().unwrap() += 1;
            }
        } else {
            cache.insert(method.to_string(), result.clone());
        }

        result
    }

    /// Analyze method characteristics
    fn analyze_method(&self, method: &str) -> MethodAnalysis {
        let mut analysis = MethodAnalysis::default();

        // Basic checks
        analysis.is_empty = method.is_empty();
        analysis.is_single_char = method.len() == 1;
        analysis.is_long_method = method.len() > 20;

        if analysis.is_empty {
            return analysis;
        }

        // Character analysis
        analysis.has_whitespace = method.contains(' ') || method.contains('\t');
        analysis.has_control_chars = method.chars().any(|c| c.is_control());
        analysis.has_lowercase = method.chars().any(|c| c.is_lowercase());
        analysis.has_numbers = method.chars().any(|c| c.is_numeric());

        // Check for special characters (not valid in HTTP tokens)
        analysis.has_special_chars = method.chars().any(|c| {
            match c {
                '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '.' |
                '^' | '_' | '`' | '|' | '~' => false, // Valid token characters
                _ if c.is_alphanumeric() => false,     // Alphanumeric is valid
                _ => true,                             // Everything else is special/invalid
            }
        });

        // Check for standard HTTP methods
        analysis.is_standard_method = matches!(method,
            "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" |
            "TRACE" | "CONNECT" | "PATCH"
        );

        // Check for well-known extension methods
        analysis.is_webdav_method = matches!(method,
            "PROPFIND" | "PROPPATCH" | "MKCOL" | "COPY" | "MOVE" |
            "LOCK" | "UNLOCK" | "REPORT" | "CHECKOUT" | "CHECKIN" |
            "UNCHECKOUT" | "MKWORKSPACE" | "UPDATE" | "LABEL" |
            "MERGE" | "BASELINE-CONTROL" | "MKACTIVITY"
        );

        // Check for custom application methods
        if !analysis.is_standard_method && !analysis.is_webdav_method {
            analysis.is_custom_method = self.is_well_formed_custom_method(method);
        }

        analysis
    }

    /// Check if method is a well-formed custom method
    fn is_well_formed_custom_method(&self, method: &str) -> bool {
        // Must be all uppercase letters/numbers and valid token characters
        !method.is_empty() &&
        method.chars().all(|c| {
            c.is_ascii_uppercase() || c.is_ascii_digit() ||
            matches!(c, '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' |
                       '-' | '.' | '^' | '_' | '`' | '|' | '~')
        })
    }

    /// Validate method format per RFC 9110 requirements
    fn validate_method_format(&self, method: &str, analysis: &MethodAnalysis) -> bool {
        // RFC 9110: method must be a token
        if analysis.is_empty {
            return false;
        }

        // No whitespace allowed
        if analysis.has_whitespace {
            return false;
        }

        // No control characters allowed
        if analysis.has_control_chars {
            return false;
        }

        // No invalid special characters
        if analysis.has_special_chars {
            return false;
        }

        // Method should be uppercase (convention, not strict requirement)
        // But we'll be lenient for extension methods
        if analysis.has_lowercase && analysis.is_standard_method {
            return false; // Standard methods must be uppercase
        }

        // Very long methods might be problematic
        if method.len() > 255 {
            return false; // Reasonable limit
        }

        // Must be a valid token per RFC 9110 §5.6.2
        self.is_valid_token(method)
    }

    /// Check if string is a valid HTTP token
    fn is_valid_token(&self, s: &str) -> bool {
        !s.is_empty() && s.chars().all(|c| {
            c.is_ascii_alphanumeric() ||
            matches!(c, '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' |
                       '-' | '.' | '^' | '_' | '`' | '|' | '~')
        })
    }

    /// Check if two results match (for consistency validation)
    fn results_match(&self, result1: &ExtensionMethodResult, result2: &ExtensionMethodResult) -> bool {
        match (result1, result2) {
            (ExtensionMethodResult::Accepted, ExtensionMethodResult::Accepted) => true,
            (ExtensionMethodResult::BadRequest(_), ExtensionMethodResult::BadRequest(_)) => true,
            _ => false,
        }
    }

    /// Generate summary statistics
    fn generate_statistics(&self) -> ExtensionMethodStatistics {
        ExtensionMethodStatistics {
            total_webdav: *self.webdav_methods.lock().unwrap(),
            total_custom: *self.custom_methods.lock().unwrap(),
            total_numeric: *self.numeric_methods.lock().unwrap(),
            total_long: *self.long_methods.lock().unwrap(),
            total_single_char: *self.single_char_methods.lock().unwrap(),
            total_whitespace: *self.whitespace_methods.lock().unwrap(),
            total_control_chars: *self.control_char_methods.lock().unwrap(),
            total_lowercase: *self.lowercase_methods.lock().unwrap(),
            total_special_chars: *self.special_char_methods.lock().unwrap(),
            total_empty: *self.empty_methods.lock().unwrap(),
            total_accepted_extensions: *self.accepted_extensions.lock().unwrap(),
            total_rejected: *self.rejected_methods.lock().unwrap(),
            total_standard: *self.standard_methods.lock().unwrap(),
            consistency_violations: *self.consistency_violations.lock().unwrap(),
        }
    }
}

#[derive(Debug, Default)]
struct MethodAnalysis {
    pub is_empty: bool,
    pub is_single_char: bool,
    pub is_long_method: bool,
    pub has_whitespace: bool,
    pub has_control_chars: bool,
    pub has_lowercase: bool,
    pub has_numbers: bool,
    pub has_special_chars: bool,
    pub is_standard_method: bool,
    pub is_webdav_method: bool,
    pub is_custom_method: bool,
}

#[derive(Debug, Clone)]
enum ExtensionMethodResult {
    Accepted,
    BadRequest(&'static str),
}

#[derive(Debug)]
struct ExtensionMethodStatistics {
    pub total_webdav: u64,
    pub total_custom: u64,
    pub total_numeric: u64,
    pub total_long: u64,
    pub total_single_char: u64,
    pub total_whitespace: u64,
    pub total_control_chars: u64,
    pub total_lowercase: u64,
    pub total_special_chars: u64,
    pub total_empty: u64,
    pub total_accepted_extensions: u64,
    pub total_rejected: u64,
    pub total_standard: u64,
    pub consistency_violations: u64,
}

/// Fuzz input structure for extension method testing
#[derive(Arbitrary, Debug)]
struct ExtensionMethodInput {
    /// Base method name
    base_method: String,
    /// Additional characters to append
    extra_chars: String,
    /// Test scenario configuration
    scenario: ExtensionMethodScenario,
    /// Length multiplier for stress testing
    length_multiplier: u8,
}

#[derive(Arbitrary, Debug, Clone)]
enum ExtensionMethodScenario {
    /// WebDAV extension methods
    WebDavMethod,
    /// Custom application methods
    CustomMethod,
    /// Methods with numbers
    NumericMethod,
    /// Long method names
    LongMethod,
    /// Single character methods
    SingleChar,
    /// Invalid: methods with whitespace
    WhitespaceMethod,
    /// Invalid: methods with control characters
    ControlCharMethod,
    /// Invalid: lowercase methods
    LowercaseMethod,
    /// Invalid: methods with special characters
    SpecialCharMethod,
    /// Invalid: empty method
    EmptyMethod,
    /// Standard methods (for comparison)
    StandardMethod,
    /// Boundary testing
    BoundaryMethod,
}

impl ExtensionMethodInput {
    /// Generate method name based on the test scenario
    fn generate_method(&self) -> String {
        match &self.scenario {
            ExtensionMethodScenario::WebDavMethod => {
                // Well-known WebDAV extension methods
                let webdav_methods = [
                    "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE",
                    "LOCK", "UNLOCK", "REPORT", "CHECKOUT", "CHECKIN",
                    "UNCHECKOUT", "MKWORKSPACE", "UPDATE", "LABEL",
                    "MERGE", "BASELINE-CONTROL", "MKACTIVITY"
                ];
                let index = (self.length_multiplier as usize) % webdav_methods.len();
                webdav_methods[index].to_string()
            }

            ExtensionMethodScenario::CustomMethod => {
                // Custom application methods
                if !self.base_method.is_empty() {
                    self.base_method.to_uppercase()
                } else {
                    let custom_methods = [
                        "BREW", "COFFEE", "TEAPOT", "HELLO", "PING",
                        "SUBSCRIBE", "UNSUBSCRIBE", "NOTIFY", "PUBLISH",
                        "DISCOVER", "REGISTER", "UNREGISTER"
                    ];
                    let index = (self.length_multiplier as usize) % custom_methods.len();
                    custom_methods[index].to_string()
                }
            }

            ExtensionMethodScenario::NumericMethod => {
                // Methods with numbers
                if !self.base_method.is_empty() {
                    format!("{}{}", self.base_method.to_uppercase(), self.length_multiplier)
                } else {
                    format!("HTTP{}", self.length_multiplier % 10)
                }
            }

            ExtensionMethodScenario::LongMethod => {
                // Very long method names
                let mut method = if self.base_method.is_empty() {
                    "VERYLONGCUSTOMMETHOD".to_string()
                } else {
                    self.base_method.to_uppercase()
                };

                let repeat_count = (self.length_multiplier as usize % 10) + 5;
                for i in 0..repeat_count {
                    method.push_str(&format!("SEGMENT{}", i));
                    if method.len() > 200 {
                        break;
                    }
                }
                method
            }

            ExtensionMethodScenario::SingleChar => {
                // Single character methods
                let chars = ['A', 'B', 'C', 'X', 'Y', 'Z'];
                let index = (self.length_multiplier as usize) % chars.len();
                chars[index].to_string()
            }

            ExtensionMethodScenario::WhitespaceMethod => {
                // Invalid: methods with whitespace
                if !self.base_method.is_empty() {
                    format!("{} METHOD", self.base_method)
                } else {
                    "GET POST".to_string()
                }
            }

            ExtensionMethodScenario::ControlCharMethod => {
                // Invalid: methods with control characters
                if !self.base_method.is_empty() {
                    format!("{}\n", self.base_method)
                } else {
                    "METHOD\r\n".to_string()
                }
            }

            ExtensionMethodScenario::LowercaseMethod => {
                // Invalid: lowercase methods (for standard methods)
                if !self.base_method.is_empty() {
                    self.base_method.to_lowercase()
                } else {
                    "get".to_string()
                }
            }

            ExtensionMethodScenario::SpecialCharMethod => {
                // Invalid: methods with special characters
                if !self.base_method.is_empty() {
                    format!("{}!", self.base_method)
                } else {
                    "METHOD@HOST".to_string()
                }
            }

            ExtensionMethodScenario::EmptyMethod => {
                // Invalid: empty method
                String::new()
            }

            ExtensionMethodScenario::StandardMethod => {
                // Standard HTTP methods (for comparison)
                let standard_methods = [
                    "GET", "POST", "PUT", "DELETE", "HEAD",
                    "OPTIONS", "TRACE", "CONNECT", "PATCH"
                ];
                let index = (self.length_multiplier as usize) % standard_methods.len();
                standard_methods[index].to_string()
            }

            ExtensionMethodScenario::BoundaryMethod => {
                // Boundary testing
                match self.length_multiplier % 4 {
                    0 => "A".to_string(),                    // Minimal valid
                    1 => "Z".repeat(255),                    // Maximum length
                    2 => "METHOD-WITH-HYPHENS".to_string(),  // Hyphens (valid token char)
                    _ => "METHOD_WITH_UNDERSCORES".to_string(), // Underscores (valid)
                }
            }
        }
    }
}

fuzz_target!(|input: ExtensionMethodInput| {
    // Skip excessively large inputs
    if input.base_method.len() > 1000 || input.extra_chars.len() > 100 {
        return;
    }

    // Generate test configuration
    let config = ExtensionMethodTestConfig::default();

    // Create mock connection
    let connection = MockExtensionMethodConnection::new(config);

    // Generate method for testing
    let method = input.generate_method();

    // Limit method length to prevent OOM
    if method.len() > 1024 {
        return;
    }

    // Test the extension method validation
    let result = connection.handle_extension_method_request(&method);

    // Verify the result makes sense based on method characteristics
    match result {
        ExtensionMethodResult::Accepted => {
            // Should be accepted if it's a valid token (standard or extension)
            if method.is_empty() {
                panic!("Empty method should not be accepted");
            }
            if method.contains(' ') || method.contains('\t') {
                panic!("Method with whitespace should not be accepted: '{}'", method);
            }
            if method.chars().any(|c| c.is_control()) {
                panic!("Method with control characters should not be accepted: '{}'", method);
            }
        }
        ExtensionMethodResult::BadRequest(_reason) => {
            // Should be rejected for invalid token format
        }
    }

    // Test consistency: same input should yield same result
    let result2 = connection.handle_extension_method_request(&method);
    if !connection.results_match(&result, &result2) {
        panic!("Inconsistent extension method validation: {:?} != {:?} for method: '{}'",
               result, result2, method);
    }

    // Generate statistics for analysis
    let _stats = connection.generate_statistics();

    // Verify no consistency violations were detected internally
    assert_eq!(*connection.consistency_violations.lock().unwrap(), 0,
               "Internal consistency violations detected");

    // For valid extension method scenarios, verify acceptance
    match input.scenario {
        ExtensionMethodScenario::WebDavMethod |
        ExtensionMethodScenario::CustomMethod |
        ExtensionMethodScenario::StandardMethod => {
            if connection.is_valid_token(&method) && !method.is_empty() {
                match result {
                    ExtensionMethodResult::Accepted => {
                        // Correct: valid extension methods should be accepted
                    }
                    ExtensionMethodResult::BadRequest(_) => {
                        // Only acceptable if method has invalid characters
                        if !method.chars().any(|c| c.is_whitespace() || c.is_control()) &&
                           connection.is_valid_token(&method) {
                            panic!("Valid extension method '{}' should be accepted per RFC 9110 §9.1", method);
                        }
                    }
                }
            }
        }
        ExtensionMethodScenario::WhitespaceMethod |
        ExtensionMethodScenario::ControlCharMethod |
        ExtensionMethodScenario::SpecialCharMethod |
        ExtensionMethodScenario::EmptyMethod => {
            // Invalid methods should be rejected
            match result {
                ExtensionMethodResult::BadRequest(_) => {
                    // Correct: invalid methods should be rejected
                }
                ExtensionMethodResult::Accepted => {
                    // Only acceptable if the generated method is actually valid
                    if method.is_empty() || method.chars().any(|c| c.is_whitespace() || c.is_control()) ||
                       !connection.is_valid_token(&method) {
                        panic!("Invalid method '{}' should be rejected", method);
                    }
                }
            }
        }
        _ => {
            // Other scenarios have their own validation requirements
        }
    }
});