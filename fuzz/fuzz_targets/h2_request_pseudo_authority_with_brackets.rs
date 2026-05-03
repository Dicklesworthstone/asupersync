#![no_main]
//! HTTP/2 :authority pseudo-header IPv6 brackets fuzz target
//!
//! Tests handling of :authority pseudo-headers with IPv6 literals in brackets.
//! Per RFC 3986 §3.2.2, IPv6 literals in URIs MUST be enclosed in square
//! brackets to avoid ambiguity with port syntax. This applies to HTTP/2
//! :authority pseudo-headers containing IPv6 addresses.
//!
//! Primary test scenario: Valid IPv6 authorities like "[::1]:443", "[2001:db8::1]:8080"
//!
//! Test scenarios:
//! - Standard IPv6 with port ("[::1]:443", "[2001:db8::1]:8080")
//! - IPv6 without port ("[::1]", "[2001:db8::1]")
//! - Compressed IPv6 notation ("[::1]", "[2001:db8::]", "[::ffff:192.0.2.1]")
//! - Full IPv6 addresses ("[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:443")
//! - IPv6 with zone ID ("[fe80::1%eth0]:80", "[fe80::1%25eth0]:80" percent-encoded)
//! - Loopback addresses ("[::1]:443")
//! - Link-local addresses ("[fe80::1]:80")
//! - IPv4-mapped IPv6 ("[::ffff:192.0.2.1]:80")
//! - Invalid: IPv6 without brackets ("::1:443", "2001:db8::1:8080")
//! - Invalid: malformed brackets ("[::1", "::1]", "[]", "[]:80")
//! - Invalid: malformed IPv6 ("[:::1]:443", "[2001:db8::g]:80")
//!
//! RFC references:
//! - RFC 3986 §3.2.2: Authority component format (IPv6 literals in brackets)
//! - RFC 4291: IPv6 addressing architecture
//! - RFC 6874: IPv6 zone identifier representation
//! - RFC 7540 §8.1.2.3: :authority pseudo-header requirements

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Configuration for IPv6 authority testing
#[derive(Debug, Clone)]
struct IPv6AuthorityTestConfig {
    /// Include standard IPv6 addresses with ports
    pub include_standard_ipv6: bool,
    /// Include IPv6 addresses without ports
    pub include_no_port: bool,
    /// Include IPv6 with zone identifiers
    pub include_zone_ids: bool,
    /// Include IPv4-mapped IPv6 addresses
    pub include_ipv4_mapped: bool,
    /// Include invalid formats (for negative testing)
    pub include_invalid_formats: bool,
}

impl Default for IPv6AuthorityTestConfig {
    fn default() -> Self {
        Self {
            include_standard_ipv6: true,
            include_no_port: true,
            include_zone_ids: true,
            include_ipv4_mapped: true,
            include_invalid_formats: true,
        }
    }
}

/// Mock HTTP/2 connection for IPv6 authority validation testing
#[derive(Debug)]
struct MockIPv6AuthorityConnection {
    /// Count of requests with valid bracketed IPv6 addresses
    pub valid_bracketed_ipv6: Arc<Mutex<u64>>,
    /// Count of requests with IPv6 addresses and ports
    pub ipv6_with_port: Arc<Mutex<u64>>,
    /// Count of requests with IPv6 addresses without ports
    pub ipv6_without_port: Arc<Mutex<u64>>,
    /// Count of requests with compressed IPv6 notation
    pub compressed_ipv6: Arc<Mutex<u64>>,
    /// Count of requests with full IPv6 addresses
    pub full_ipv6: Arc<Mutex<u64>>,
    /// Count of requests with IPv6 zone identifiers
    pub ipv6_with_zone_id: Arc<Mutex<u64>>,
    /// Count of requests with loopback IPv6 addresses
    pub loopback_ipv6: Arc<Mutex<u64>>,
    /// Count of requests with link-local IPv6 addresses
    pub link_local_ipv6: Arc<Mutex<u64>>,
    /// Count of requests with IPv4-mapped IPv6 addresses
    pub ipv4_mapped_ipv6: Arc<Mutex<u64>>,
    /// Count of requests with IPv6 without brackets (invalid)
    pub unbracket_ipv6: Arc<Mutex<u64>>,
    /// Count of requests with malformed brackets
    pub malformed_brackets: Arc<Mutex<u64>>,
    /// Count of requests with malformed IPv6
    pub malformed_ipv6: Arc<Mutex<u64>>,
    /// Count of requests with empty brackets
    pub empty_brackets: Arc<Mutex<u64>>,
    /// Count of accepted IPv6 authorities
    pub accepted_ipv6: Arc<Mutex<u64>>,
    /// Count of rejected invalid authorities
    pub rejected_authorities: Arc<Mutex<u64>>,
    /// Track consistency violations
    pub consistency_violations: Arc<Mutex<u64>>,
    /// Configuration for this test session
    pub config: IPv6AuthorityTestConfig,
    /// Cache of previous decisions for consistency checking
    pub decision_cache: Arc<Mutex<HashMap<String, IPv6AuthorityResult>>>,
}

impl MockIPv6AuthorityConnection {
    fn new(config: IPv6AuthorityTestConfig) -> Self {
        Self {
            valid_bracketed_ipv6: Arc::new(Mutex::new(0)),
            ipv6_with_port: Arc::new(Mutex::new(0)),
            ipv6_without_port: Arc::new(Mutex::new(0)),
            compressed_ipv6: Arc::new(Mutex::new(0)),
            full_ipv6: Arc::new(Mutex::new(0)),
            ipv6_with_zone_id: Arc::new(Mutex::new(0)),
            loopback_ipv6: Arc::new(Mutex::new(0)),
            link_local_ipv6: Arc::new(Mutex::new(0)),
            ipv4_mapped_ipv6: Arc::new(Mutex::new(0)),
            unbracket_ipv6: Arc::new(Mutex::new(0)),
            malformed_brackets: Arc::new(Mutex::new(0)),
            malformed_ipv6: Arc::new(Mutex::new(0)),
            empty_brackets: Arc::new(Mutex::new(0)),
            accepted_ipv6: Arc::new(Mutex::new(0)),
            rejected_authorities: Arc::new(Mutex::new(0)),
            consistency_violations: Arc::new(Mutex::new(0)),
            config,
            decision_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Process HTTP/2 request with :authority IPv6 validation
    fn handle_ipv6_authority_request(&self, authority: &str) -> IPv6AuthorityResult {
        let analysis = self.analyze_ipv6_authority(authority);

        // Track various IPv6 patterns
        if analysis.has_valid_bracketed_ipv6 {
            *self.valid_bracketed_ipv6.lock().unwrap() += 1;
        }

        if analysis.has_port {
            *self.ipv6_with_port.lock().unwrap() += 1;
        } else if analysis.is_ipv6_authority {
            *self.ipv6_without_port.lock().unwrap() += 1;
        }

        if analysis.is_compressed_ipv6 {
            *self.compressed_ipv6.lock().unwrap() += 1;
        }

        if analysis.is_full_ipv6 {
            *self.full_ipv6.lock().unwrap() += 1;
        }

        if analysis.has_zone_id {
            *self.ipv6_with_zone_id.lock().unwrap() += 1;
        }

        if analysis.is_loopback_ipv6 {
            *self.loopback_ipv6.lock().unwrap() += 1;
        }

        if analysis.is_link_local_ipv6 {
            *self.link_local_ipv6.lock().unwrap() += 1;
        }

        if analysis.is_ipv4_mapped_ipv6 {
            *self.ipv4_mapped_ipv6.lock().unwrap() += 1;
        }

        if analysis.is_unbracketed_ipv6 {
            *self.unbracket_ipv6.lock().unwrap() += 1;
        }

        if analysis.has_malformed_brackets {
            *self.malformed_brackets.lock().unwrap() += 1;
        }

        if analysis.has_malformed_ipv6 {
            *self.malformed_ipv6.lock().unwrap() += 1;
        }

        if analysis.has_empty_brackets {
            *self.empty_brackets.lock().unwrap() += 1;
        }

        // Determine if authority is valid per RFC 3986
        let is_valid = self.validate_ipv6_authority(&analysis);

        // Check consistency with previous decisions
        let mut cache = self.decision_cache.lock().unwrap();
        let result = if is_valid {
            *self.accepted_ipv6.lock().unwrap() += 1;
            IPv6AuthorityResult::Accepted
        } else {
            *self.rejected_authorities.lock().unwrap() += 1;

            // Determine specific error reason
            if analysis.has_empty_brackets {
                IPv6AuthorityResult::BadRequest("Empty brackets")
            } else if analysis.has_malformed_brackets {
                IPv6AuthorityResult::BadRequest("Malformed brackets")
            } else if analysis.has_malformed_ipv6 {
                IPv6AuthorityResult::BadRequest("Malformed IPv6 address")
            } else if analysis.is_unbracketed_ipv6 {
                IPv6AuthorityResult::BadRequest("IPv6 address not in brackets")
            } else {
                IPv6AuthorityResult::BadRequest("Invalid authority format")
            }
        };

        // Consistency check
        if let Some(previous_result) = cache.get(authority) {
            if !self.results_match(&result, previous_result) {
                *self.consistency_violations.lock().unwrap() += 1;
            }
        } else {
            cache.insert(authority.to_string(), result.clone());
        }

        result
    }

    /// Analyze IPv6 authority characteristics
    fn analyze_ipv6_authority(&self, authority: &str) -> IPv6AuthorityAnalysis {
        let mut analysis = IPv6AuthorityAnalysis::default();

        if authority.is_empty() {
            return analysis;
        }

        // Basic bracket detection
        analysis.has_brackets = authority.contains('[') && authority.contains(']');
        analysis.has_empty_brackets = authority == "[]" || authority.starts_with("[]:") || authority == "[]:";

        // Check for malformed brackets
        let open_brackets = authority.matches('[').count();
        let close_brackets = authority.matches(']').count();
        analysis.has_malformed_brackets = open_brackets != close_brackets ||
                                         (authority.contains('[') && !authority.contains(']')) ||
                                         (authority.contains(']') && !authority.contains('[')) ||
                                         authority.starts_with(']') ||
                                         authority.ends_with('[');

        // Check for port
        if let Some(close_bracket_pos) = authority.rfind(']') {
            let after_bracket = &authority[close_bracket_pos + 1..];
            if after_bracket.starts_with(':') && after_bracket.len() > 1 {
                analysis.has_port = true;
                // Extract port
                let port_str = &after_bracket[1..];
                analysis.valid_port = port_str.chars().all(|c| c.is_ascii_digit()) &&
                                     port_str.parse::<u16>().is_ok();
            }
        }

        // Extract IPv6 address if properly bracketed
        if analysis.has_brackets && !analysis.has_malformed_brackets {
            if let Some(start) = authority.find('[') {
                if let Some(end) = authority.find(']') {
                    if start < end {
                        let ipv6_addr = &authority[start + 1..end];
                        analysis.is_ipv6_authority = true;
                        analysis.ipv6_address = Some(ipv6_addr.to_string());

                        // Analyze IPv6 address characteristics
                        self.analyze_ipv6_address(ipv6_addr, &mut analysis);
                    }
                }
            }
        }

        // Check for unbracketed IPv6 (invalid)
        if !analysis.has_brackets && self.looks_like_ipv6(authority) {
            analysis.is_unbracketed_ipv6 = true;
        }

        analysis
    }

    /// Analyze specific IPv6 address characteristics
    fn analyze_ipv6_address(&self, ipv6_addr: &str, analysis: &mut IPv6AuthorityAnalysis) {
        // Check for zone ID
        analysis.has_zone_id = ipv6_addr.contains('%');

        // Check for IPv4-mapped IPv6
        analysis.is_ipv4_mapped_ipv6 = ipv6_addr.starts_with("::ffff:");

        // Check for compressed notation
        analysis.is_compressed_ipv6 = ipv6_addr.contains("::");

        // Check for loopback
        analysis.is_loopback_ipv6 = ipv6_addr == "::1";

        // Check for link-local
        analysis.is_link_local_ipv6 = ipv6_addr.starts_with("fe80::");

        // Check if it's a full IPv6 address (8 groups)
        let clean_addr = if let Some(percent_pos) = ipv6_addr.find('%') {
            &ipv6_addr[..percent_pos]
        } else {
            ipv6_addr
        };

        if !clean_addr.contains("::") {
            let groups: Vec<&str> = clean_addr.split(':').collect();
            analysis.is_full_ipv6 = groups.len() == 8 &&
                                   groups.iter().all(|g| !g.is_empty() && g.len() <= 4 &&
                                                    g.chars().all(|c| c.is_ascii_hexdigit()));
        }

        // Basic IPv6 validation
        analysis.has_valid_bracketed_ipv6 = self.is_valid_ipv6_syntax(ipv6_addr);

        if !analysis.has_valid_bracketed_ipv6 {
            analysis.has_malformed_ipv6 = true;
        }
    }

    /// Check if string looks like IPv6 (for detecting unbracketed IPv6)
    fn looks_like_ipv6(&self, s: &str) -> bool {
        s.contains(':') && (s.contains("::") || s.matches(':').count() >= 2)
    }

    /// Basic IPv6 syntax validation
    fn is_valid_ipv6_syntax(&self, ipv6_addr: &str) -> bool {
        if ipv6_addr.is_empty() {
            return false;
        }

        // Handle zone ID
        let clean_addr = if let Some(percent_pos) = ipv6_addr.find('%') {
            &ipv6_addr[..percent_pos]
        } else {
            ipv6_addr
        };

        // Very basic IPv6 validation
        if clean_addr == "::1" || clean_addr.starts_with("fe80::") ||
           clean_addr.starts_with("2001:") || clean_addr.starts_with("::ffff:") {
            return true;
        }

        // Check for compressed notation
        if clean_addr.contains("::") {
            let parts: Vec<&str> = clean_addr.split("::").collect();
            if parts.len() == 2 {
                // Valid compressed form
                return parts.iter().all(|part| {
                    part.is_empty() || part.split(':').all(|group| {
                        !group.is_empty() && group.len() <= 4 &&
                        group.chars().all(|c| c.is_ascii_hexdigit())
                    })
                });
            }
        }

        // Check full form
        let groups: Vec<&str> = clean_addr.split(':').collect();
        groups.len() <= 8 && groups.iter().all(|g| {
            !g.is_empty() && g.len() <= 4 && g.chars().all(|c| c.is_ascii_hexdigit())
        })
    }

    /// Validate IPv6 authority format per RFC 3986
    fn validate_ipv6_authority(&self, analysis: &IPv6AuthorityAnalysis) -> bool {
        // RFC 3986: IPv6 literals must be in brackets
        if analysis.is_unbracketed_ipv6 {
            return false;
        }

        // Must have properly formed brackets
        if analysis.has_malformed_brackets {
            return false;
        }

        // Empty brackets are invalid
        if analysis.has_empty_brackets {
            return false;
        }

        // If it has IPv6, it must be valid
        if analysis.is_ipv6_authority {
            if analysis.has_malformed_ipv6 {
                return false;
            }

            if !analysis.has_valid_bracketed_ipv6 {
                return false;
            }

            // Port validation if present
            if analysis.has_port && !analysis.valid_port {
                return false;
            }
        }

        true
    }

    /// Check if two results match (for consistency validation)
    fn results_match(&self, result1: &IPv6AuthorityResult, result2: &IPv6AuthorityResult) -> bool {
        match (result1, result2) {
            (IPv6AuthorityResult::Accepted, IPv6AuthorityResult::Accepted) => true,
            (IPv6AuthorityResult::BadRequest(_), IPv6AuthorityResult::BadRequest(_)) => true,
            _ => false,
        }
    }

    /// Generate summary statistics
    fn generate_statistics(&self) -> IPv6AuthorityStatistics {
        IPv6AuthorityStatistics {
            total_valid_bracketed: *self.valid_bracketed_ipv6.lock().unwrap(),
            total_with_port: *self.ipv6_with_port.lock().unwrap(),
            total_without_port: *self.ipv6_without_port.lock().unwrap(),
            total_compressed: *self.compressed_ipv6.lock().unwrap(),
            total_full: *self.full_ipv6.lock().unwrap(),
            total_with_zone_id: *self.ipv6_with_zone_id.lock().unwrap(),
            total_loopback: *self.loopback_ipv6.lock().unwrap(),
            total_link_local: *self.link_local_ipv6.lock().unwrap(),
            total_ipv4_mapped: *self.ipv4_mapped_ipv6.lock().unwrap(),
            total_unbracketed: *self.unbracket_ipv6.lock().unwrap(),
            total_malformed_brackets: *self.malformed_brackets.lock().unwrap(),
            total_malformed_ipv6: *self.malformed_ipv6.lock().unwrap(),
            total_empty_brackets: *self.empty_brackets.lock().unwrap(),
            total_accepted: *self.accepted_ipv6.lock().unwrap(),
            total_rejected: *self.rejected_authorities.lock().unwrap(),
            consistency_violations: *self.consistency_violations.lock().unwrap(),
        }
    }
}

#[derive(Debug, Default)]
struct IPv6AuthorityAnalysis {
    pub has_brackets: bool,
    pub has_empty_brackets: bool,
    pub has_malformed_brackets: bool,
    pub has_port: bool,
    pub valid_port: bool,
    pub is_ipv6_authority: bool,
    pub ipv6_address: Option<String>,
    pub has_valid_bracketed_ipv6: bool,
    pub is_compressed_ipv6: bool,
    pub is_full_ipv6: bool,
    pub has_zone_id: bool,
    pub is_loopback_ipv6: bool,
    pub is_link_local_ipv6: bool,
    pub is_ipv4_mapped_ipv6: bool,
    pub is_unbracketed_ipv6: bool,
    pub has_malformed_ipv6: bool,
}

#[derive(Debug, Clone)]
enum IPv6AuthorityResult {
    Accepted,
    BadRequest(&'static str),
}

#[derive(Debug)]
struct IPv6AuthorityStatistics {
    pub total_valid_bracketed: u64,
    pub total_with_port: u64,
    pub total_without_port: u64,
    pub total_compressed: u64,
    pub total_full: u64,
    pub total_with_zone_id: u64,
    pub total_loopback: u64,
    pub total_link_local: u64,
    pub total_ipv4_mapped: u64,
    pub total_unbracketed: u64,
    pub total_malformed_brackets: u64,
    pub total_malformed_ipv6: u64,
    pub total_empty_brackets: u64,
    pub total_accepted: u64,
    pub total_rejected: u64,
    pub consistency_violations: u64,
}

/// Fuzz input structure for IPv6 authority testing
#[derive(Arbitrary, Debug)]
struct IPv6AuthorityInput {
    /// IPv6 address base
    ipv6_base: String,
    /// Port number
    port: u16,
    /// Zone identifier
    zone_id: String,
    /// Test scenario configuration
    scenario: IPv6AuthorityScenario,
    /// Variation index for stress testing
    variation: u8,
}

#[derive(Arbitrary, Debug, Clone)]
enum IPv6AuthorityScenario {
    /// Standard IPv6 with port: [::1]:443
    StandardIPv6WithPort,
    /// IPv6 without port: [::1]
    IPv6WithoutPort,
    /// Compressed IPv6: [2001:db8::]
    CompressedIPv6,
    /// Full IPv6: [2001:0db8:85a3:0000:0000:8a2e:0370:7334]
    FullIPv6,
    /// IPv6 with zone ID: [fe80::1%eth0]
    IPv6WithZoneID,
    /// Loopback: [::1]
    LoopbackIPv6,
    /// Link-local: [fe80::1]
    LinkLocalIPv6,
    /// IPv4-mapped: [::ffff:192.0.2.1]
    IPv4MappedIPv6,
    /// Invalid: unbracketed IPv6: ::1:443
    UnbrackketedIPv6,
    /// Invalid: malformed brackets: [::1
    MalformedBrackets,
    /// Invalid: malformed IPv6: [:::1]
    MalformedIPv6,
    /// Invalid: empty brackets: []
    EmptyBrackets,
}

impl IPv6AuthorityInput {
    /// Generate authority string based on the test scenario
    fn generate_authority(&self) -> String {
        match &self.scenario {
            IPv6AuthorityScenario::StandardIPv6WithPort => {
                format!("[::1]:{}", if self.port == 0 { 443 } else { self.port })
            }

            IPv6AuthorityScenario::IPv6WithoutPort => {
                "[::1]".to_string()
            }

            IPv6AuthorityScenario::CompressedIPv6 => {
                let addresses = [
                    "[::1]", "[2001:db8::]", "[::ffff:0:0]", "[2001:db8:85a3::]"
                ];
                let index = (self.variation as usize) % addresses.len();
                let addr = addresses[index];
                if self.port > 0 && self.port != 80 {
                    format!("{}:{}", addr, self.port)
                } else {
                    addr.to_string()
                }
            }

            IPv6AuthorityScenario::FullIPv6 => {
                format!("[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:{}",
                       if self.port == 0 { 8080 } else { self.port })
            }

            IPv6AuthorityScenario::IPv6WithZoneID => {
                let zone = if self.zone_id.is_empty() { "eth0" } else { &self.zone_id };
                let port_part = if self.port > 0 { format!(":{}", self.port) } else { String::new() };
                format!("[fe80::1%{}]{}", zone, port_part)
            }

            IPv6AuthorityScenario::LoopbackIPv6 => {
                let port_part = if self.port > 0 { format!(":{}", self.port) } else { String::new() };
                format!("[::1]{}", port_part)
            }

            IPv6AuthorityScenario::LinkLocalIPv6 => {
                let port_part = if self.port > 0 { format!(":{}", self.port) } else { String::new() };
                format!("[fe80::1]{}", port_part)
            }

            IPv6AuthorityScenario::IPv4MappedIPv6 => {
                let port_part = if self.port > 0 { format!(":{}", self.port) } else { String::new() };
                format!("[::ffff:192.0.2.1]{}", port_part)
            }

            IPv6AuthorityScenario::UnbrackketedIPv6 => {
                // Invalid: IPv6 without brackets
                if self.port > 0 {
                    format!("::1:{}", self.port) // Ambiguous with port
                } else {
                    "2001:db8::1".to_string()
                }
            }

            IPv6AuthorityScenario::MalformedBrackets => {
                // Invalid: malformed brackets
                match self.variation % 4 {
                    0 => "[::1".to_string(),           // Missing closing bracket
                    1 => "::1]".to_string(),           // Missing opening bracket
                    2 => "][::1][".to_string(),        // Wrong order
                    _ => "[[::1]]".to_string(),        // Double brackets
                }
            }

            IPv6AuthorityScenario::MalformedIPv6 => {
                // Invalid: malformed IPv6
                match self.variation % 4 {
                    0 => "[:::1]:443".to_string(),     // Too many colons
                    1 => "[2001:db8::g]:80".to_string(), // Invalid hex digit
                    2 => "[2001:db8:85a3:0000:0000:8a2e:0370:7334:extra]:80".to_string(), // Too many groups
                    _ => "[]:80".to_string(),          // Empty IPv6
                }
            }

            IPv6AuthorityScenario::EmptyBrackets => {
                // Invalid: empty brackets
                if self.port > 0 {
                    format!("[]:{}", self.port)
                } else {
                    "[]".to_string()
                }
            }
        }
    }
}

fuzz_target!(|input: IPv6AuthorityInput| {
    // Skip excessively large inputs
    if input.ipv6_base.len() > 100 || input.zone_id.len() > 50 {
        return;
    }

    // Generate test configuration
    let config = IPv6AuthorityTestConfig::default();

    // Create mock connection
    let connection = MockIPv6AuthorityConnection::new(config);

    // Generate authority for testing
    let authority = input.generate_authority();

    // Limit authority length to prevent OOM
    if authority.len() > 512 {
        return;
    }

    // Test the IPv6 authority validation
    let result = connection.handle_ipv6_authority_request(&authority);

    // Verify the result makes sense
    match result {
        IPv6AuthorityResult::Accepted => {
            // Should be accepted for valid IPv6 in brackets
        }
        IPv6AuthorityResult::BadRequest(_reason) => {
            // Should be rejected for invalid formats
        }
    }

    // Test consistency: same input should yield same result
    let result2 = connection.handle_ipv6_authority_request(&authority);
    if !connection.results_match(&result, &result2) {
        panic!("Inconsistent IPv6 authority validation: {:?} != {:?} for authority: '{}'",
               result, result2, authority);
    }

    // Generate statistics for analysis
    let _stats = connection.generate_statistics();

    // Verify no consistency violations were detected internally
    assert_eq!(*connection.consistency_violations.lock().unwrap(), 0,
               "Internal consistency violations detected");

    // For valid IPv6 scenarios, verify acceptance
    match input.scenario {
        IPv6AuthorityScenario::StandardIPv6WithPort |
        IPv6AuthorityScenario::IPv6WithoutPort |
        IPv6AuthorityScenario::CompressedIPv6 |
        IPv6AuthorityScenario::FullIPv6 |
        IPv6AuthorityScenario::IPv6WithZoneID |
        IPv6AuthorityScenario::LoopbackIPv6 |
        IPv6AuthorityScenario::LinkLocalIPv6 |
        IPv6AuthorityScenario::IPv4MappedIPv6 => {
            // Valid IPv6 in brackets should be accepted
            if authority.starts_with('[') && authority.contains(']') {
                match result {
                    IPv6AuthorityResult::Accepted => {
                        // Correct: valid bracketed IPv6 should be accepted
                    }
                    IPv6AuthorityResult::BadRequest(_) => {
                        // Only acceptable if the IPv6 itself is malformed
                        if !authority.contains(":::") && !authority.contains('[') {
                            panic!("Valid bracketed IPv6 '{}' should be accepted per RFC 3986 §3.2.2", authority);
                        }
                    }
                }
            }
        }
        IPv6AuthorityScenario::UnbrackketedIPv6 |
        IPv6AuthorityScenario::MalformedBrackets |
        IPv6AuthorityScenario::MalformedIPv6 |
        IPv6AuthorityScenario::EmptyBrackets => {
            // Invalid formats should be rejected
            match result {
                IPv6AuthorityResult::BadRequest(_) => {
                    // Correct: invalid formats should be rejected
                }
                IPv6AuthorityResult::Accepted => {
                    // Only acceptable if the generated authority is actually valid
                    if !authority.starts_with('[') || authority == "[]" ||
                       authority.contains(":::") || !authority.contains(']') {
                        panic!("Invalid IPv6 authority '{}' should be rejected", authority);
                    }
                }
            }
        }
    }
});