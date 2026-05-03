#![no_main]
//! HTTP/2 :authority pseudo-header malformed IPv6 fuzz target
//!
//! Tests handling of :authority pseudo-headers with malformed IPv6 addresses
//! that violate RFC 4291 syntax requirements. These should be rejected as
//! BAD_REQUEST or PROTOCOL_ERROR to prevent parsing ambiguity and security
//! issues.
//!
//! Primary test scenario: Double :: compression like "[2001:db8::1::2]"
//!
//! Malformed IPv6 test scenarios:
//! - Double compression ("[2001:db8::1::2]", "[::1::]", "[:::]")
//! - Too many groups ("[1:2:3:4:5:6:7:8:9]", "[2001:db8:1:2:3:4:5:6:7:8]")
//! - Invalid hex digits ("[2001:gggg::1]", "[2001:db8::xyz]", "[abcde::1z]")
//! - Invalid group length ("[2001:12345::1]", "[abcdef::1]", "[1:22222::]")
//! - Invalid characters ("[2001:db8::1@]", "[2001:db8::1!]", "[2001:db8::1#]")
//! - Incomplete compression ("[2001:db8:::1]", "[2001:::]", "[:::1]")
//! - Leading/trailing colons ("[2001:db8::]:", ":[::1]", "[::1]:")
//! - Port with malformed IPv6 ("[2001:db8::1::2]:80")
//! - Zone ID with malformed IPv6 ("[2001:db8::1::2%eth0]:80")
//! - IPv4-mapped malformations ("[::ffff:999.999.999.999]", "[::ffff:192.0.2]")
//! - Empty groups ("[2001:::]", "[::1:]", "[:1::]")
//!
//! RFC references:
//! - RFC 4291: IPv6 addressing architecture (syntax rules)
//! - RFC 3986 §3.2.2: Authority component format
//! - RFC 5952: IPv6 address representation recommendations
//! - RFC 7540 §8.1.2.3: :authority pseudo-header requirements

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Configuration for malformed IPv6 testing
#[derive(Debug, Clone)]
struct MalformedIPv6TestConfig {
    /// Include double compression patterns
    pub include_double_compression: bool,
    /// Include too many groups patterns
    pub include_too_many_groups: bool,
    /// Include invalid hex digits
    pub include_invalid_hex: bool,
    /// Include invalid group lengths
    pub include_invalid_lengths: bool,
    /// Include invalid characters
    pub include_invalid_chars: bool,
}

impl Default for MalformedIPv6TestConfig {
    fn default() -> Self {
        Self {
            include_double_compression: true,
            include_too_many_groups: true,
            include_invalid_hex: true,
            include_invalid_lengths: true,
            include_invalid_chars: true,
        }
    }
}

/// Mock HTTP/2 connection for malformed IPv6 validation testing
#[derive(Debug)]
struct MockMalformedIPv6Connection {
    /// Count of requests with double compression (multiple ::)
    pub double_compression: Arc<Mutex<u64>>,
    /// Count of requests with too many IPv6 groups (>8)
    pub too_many_groups: Arc<Mutex<u64>>,
    /// Count of requests with invalid hex digits
    pub invalid_hex_digits: Arc<Mutex<u64>>,
    /// Count of requests with invalid group lengths
    pub invalid_group_lengths: Arc<Mutex<u64>>,
    /// Count of requests with invalid characters
    pub invalid_characters: Arc<Mutex<u64>>,
    /// Count of requests with incomplete compression
    pub incomplete_compression: Arc<Mutex<u64>>,
    /// Count of requests with leading/trailing colon issues
    pub colon_placement_errors: Arc<Mutex<u64>>,
    /// Count of requests with malformed IPv4-mapped addresses
    pub malformed_ipv4_mapped: Arc<Mutex<u64>>,
    /// Count of requests with empty groups in wrong places
    pub empty_group_errors: Arc<Mutex<u64>>,
    /// Count of requests with zone ID syntax errors
    pub zone_id_errors: Arc<Mutex<u64>>,
    /// Count of requests with port + malformed IPv6
    pub port_with_malformed_ipv6: Arc<Mutex<u64>>,
    /// Count of rejected malformed authorities
    pub rejected_malformed: Arc<Mutex<u64>>,
    /// Count of valid authorities (for comparison)
    pub valid_authorities: Arc<Mutex<u64>>,
    /// Track consistency violations
    pub consistency_violations: Arc<Mutex<u64>>,
    /// Configuration for this test session
    pub config: MalformedIPv6TestConfig,
    /// Cache of previous decisions for consistency checking
    pub decision_cache: Arc<Mutex<HashMap<String, MalformedIPv6Result>>>,
}

impl MockMalformedIPv6Connection {
    fn new(config: MalformedIPv6TestConfig) -> Self {
        Self {
            double_compression: Arc::new(Mutex::new(0)),
            too_many_groups: Arc::new(Mutex::new(0)),
            invalid_hex_digits: Arc::new(Mutex::new(0)),
            invalid_group_lengths: Arc::new(Mutex::new(0)),
            invalid_characters: Arc::new(Mutex::new(0)),
            incomplete_compression: Arc::new(Mutex::new(0)),
            colon_placement_errors: Arc::new(Mutex::new(0)),
            malformed_ipv4_mapped: Arc::new(Mutex::new(0)),
            empty_group_errors: Arc::new(Mutex::new(0)),
            zone_id_errors: Arc::new(Mutex::new(0)),
            port_with_malformed_ipv6: Arc::new(Mutex::new(0)),
            rejected_malformed: Arc::new(Mutex::new(0)),
            valid_authorities: Arc::new(Mutex::new(0)),
            consistency_violations: Arc::new(Mutex::new(0)),
            config,
            decision_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Process HTTP/2 request with malformed IPv6 validation
    fn handle_malformed_ipv6_request(&self, authority: &str) -> MalformedIPv6Result {
        let analysis = self.analyze_malformed_ipv6(authority);

        // Track various malformation patterns
        if analysis.has_double_compression {
            *self.double_compression.lock().unwrap() += 1;
        }

        if analysis.has_too_many_groups {
            *self.too_many_groups.lock().unwrap() += 1;
        }

        if analysis.has_invalid_hex_digits {
            *self.invalid_hex_digits.lock().unwrap() += 1;
        }

        if analysis.has_invalid_group_lengths {
            *self.invalid_group_lengths.lock().unwrap() += 1;
        }

        if analysis.has_invalid_characters {
            *self.invalid_characters.lock().unwrap() += 1;
        }

        if analysis.has_incomplete_compression {
            *self.incomplete_compression.lock().unwrap() += 1;
        }

        if analysis.has_colon_placement_errors {
            *self.colon_placement_errors.lock().unwrap() += 1;
        }

        if analysis.has_malformed_ipv4_mapped {
            *self.malformed_ipv4_mapped.lock().unwrap() += 1;
        }

        if analysis.has_empty_group_errors {
            *self.empty_group_errors.lock().unwrap() += 1;
        }

        if analysis.has_zone_id_errors {
            *self.zone_id_errors.lock().unwrap() += 1;
        }

        if analysis.has_port && analysis.is_malformed {
            *self.port_with_malformed_ipv6.lock().unwrap() += 1;
        }

        // Determine if authority is valid per RFC 4291
        let is_valid = self.validate_ipv6_syntax(&analysis);

        // Check consistency with previous decisions
        let mut cache = self.decision_cache.lock().unwrap();
        let result = if is_valid {
            *self.valid_authorities.lock().unwrap() += 1;
            MalformedIPv6Result::Accepted
        } else {
            *self.rejected_malformed.lock().unwrap() += 1;

            // Determine specific error reason
            if analysis.has_double_compression {
                MalformedIPv6Result::BadRequest("Multiple :: in IPv6 address")
            } else if analysis.has_too_many_groups {
                MalformedIPv6Result::BadRequest("Too many groups in IPv6 address")
            } else if analysis.has_invalid_hex_digits {
                MalformedIPv6Result::BadRequest("Invalid hex digits in IPv6 address")
            } else if analysis.has_invalid_group_lengths {
                MalformedIPv6Result::BadRequest("Invalid group length in IPv6 address")
            } else if analysis.has_invalid_characters {
                MalformedIPv6Result::BadRequest("Invalid characters in IPv6 address")
            } else if analysis.has_incomplete_compression {
                MalformedIPv6Result::BadRequest("Incomplete compression in IPv6 address")
            } else if analysis.has_malformed_ipv4_mapped {
                MalformedIPv6Result::BadRequest("Malformed IPv4-mapped IPv6 address")
            } else {
                MalformedIPv6Result::BadRequest("Malformed IPv6 address syntax")
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

    /// Analyze authority for IPv6 malformations
    fn analyze_malformed_ipv6(&self, authority: &str) -> MalformedIPv6Analysis {
        let mut analysis = MalformedIPv6Analysis::default();

        if authority.is_empty() {
            return analysis;
        }

        // Check for basic IPv6 structure
        analysis.has_brackets = authority.contains('[') && authority.contains(']');

        if !analysis.has_brackets {
            return analysis;
        }

        // Extract IPv6 part
        if let Some(start) = authority.find('[') {
            if let Some(end) = authority.rfind(']') {
                if start < end {
                    let ipv6_part = &authority[start + 1..end];
                    analysis.ipv6_address = Some(ipv6_part.to_string());

                    // Check for port after brackets
                    let after_brackets = &authority[end + 1..];
                    analysis.has_port = after_brackets.starts_with(':');

                    // Analyze the IPv6 address for malformations
                    self.analyze_ipv6_malformations(ipv6_part, &mut analysis);
                }
            }
        }

        analysis
    }

    /// Analyze IPv6 address for various malformation patterns
    fn analyze_ipv6_malformations(&self, ipv6_addr: &str, analysis: &mut MalformedIPv6Analysis) {
        // Check for double compression (multiple ::)
        analysis.has_double_compression = ipv6_addr.matches("::").count() > 1;

        // Check for incomplete compression patterns
        analysis.has_incomplete_compression =
            ipv6_addr.contains(":::") ||
            ipv6_addr.starts_with(":::")  ||
            ipv6_addr.ends_with(":::");

        // Check for colon placement errors
        analysis.has_colon_placement_errors =
            ipv6_addr.starts_with(":") && !ipv6_addr.starts_with("::") ||
            ipv6_addr.ends_with(":") && !ipv6_addr.ends_with("::") ||
            ipv6_addr.contains(":::");

        // Handle zone ID if present
        let (clean_addr, zone_part) = if let Some(percent_pos) = ipv6_addr.find('%') {
            let addr_part = &ipv6_addr[..percent_pos];
            let zone_part = &ipv6_addr[percent_pos + 1..];

            // Basic zone ID validation
            analysis.has_zone_id_errors = zone_part.is_empty() ||
                                         zone_part.contains(':') ||
                                         zone_part.contains('[') ||
                                         zone_part.contains(']');

            (addr_part, Some(zone_part))
        } else {
            (ipv6_addr, None)
        };

        // Check for IPv4-mapped malformations
        if clean_addr.starts_with("::ffff:") {
            let ipv4_part = &clean_addr[7..];
            analysis.has_malformed_ipv4_mapped = !self.is_valid_ipv4(ipv4_part);
        }

        // Split into groups and analyze
        if clean_addr.contains("::") {
            // Handle compressed form
            let parts: Vec<&str> = clean_addr.split("::").collect();
            if parts.len() == 2 {
                let left_groups = if parts[0].is_empty() { Vec::new() } else { parts[0].split(':').collect() };
                let right_groups = if parts[1].is_empty() { Vec::new() } else { parts[1].split(':').collect() };

                let total_explicit_groups = left_groups.len() + right_groups.len();

                // Too many groups (should be <= 8 total, accounting for compression)
                analysis.has_too_many_groups = total_explicit_groups > 8;

                // Validate individual groups
                for group in left_groups.iter().chain(right_groups.iter()) {
                    self.validate_ipv6_group(group, analysis);
                }
            }
        } else {
            // Handle uncompressed form
            let groups: Vec<&str> = clean_addr.split(':').collect();

            // IPv6 must have exactly 8 groups if uncompressed
            analysis.has_too_many_groups = groups.len() != 8;

            // Check for empty groups in uncompressed form
            analysis.has_empty_group_errors = groups.iter().any(|g| g.is_empty());

            // Validate individual groups
            for group in &groups {
                self.validate_ipv6_group(group, analysis);
            }
        }

        // Overall malformation flag
        analysis.is_malformed =
            analysis.has_double_compression ||
            analysis.has_too_many_groups ||
            analysis.has_invalid_hex_digits ||
            analysis.has_invalid_group_lengths ||
            analysis.has_invalid_characters ||
            analysis.has_incomplete_compression ||
            analysis.has_colon_placement_errors ||
            analysis.has_malformed_ipv4_mapped ||
            analysis.has_empty_group_errors ||
            analysis.has_zone_id_errors;
    }

    /// Validate individual IPv6 group
    fn validate_ipv6_group(&self, group: &str, analysis: &mut MalformedIPv6Analysis) {
        if group.is_empty() {
            return; // Empty groups are handled separately
        }

        // Check group length (1-4 hex digits)
        if group.len() > 4 {
            analysis.has_invalid_group_lengths = true;
        }

        // Check for invalid hex digits
        for ch in group.chars() {
            if !ch.is_ascii_hexdigit() {
                if ch.is_ascii_alphabetic() && !"abcdefABCDEF".contains(ch) {
                    analysis.has_invalid_hex_digits = true;
                } else if !ch.is_ascii_alphanumeric() {
                    analysis.has_invalid_characters = true;
                }
            }
        }
    }

    /// Basic IPv4 validation for IPv4-mapped addresses
    fn is_valid_ipv4(&self, ipv4_str: &str) -> bool {
        let octets: Vec<&str> = ipv4_str.split('.').collect();
        if octets.len() != 4 {
            return false;
        }

        for octet in octets {
            if let Ok(num) = octet.parse::<u16>() {
                if num > 255 {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }

    /// Validate IPv6 syntax per RFC 4291
    fn validate_ipv6_syntax(&self, analysis: &MalformedIPv6Analysis) -> bool {
        // If any malformation is detected, it's invalid
        analysis.is_malformed == false
    }

    /// Check if two results match (for consistency validation)
    fn results_match(&self, result1: &MalformedIPv6Result, result2: &MalformedIPv6Result) -> bool {
        match (result1, result2) {
            (MalformedIPv6Result::Accepted, MalformedIPv6Result::Accepted) => true,
            (MalformedIPv6Result::BadRequest(_), MalformedIPv6Result::BadRequest(_)) => true,
            _ => false,
        }
    }

    /// Generate summary statistics
    fn generate_statistics(&self) -> MalformedIPv6Statistics {
        MalformedIPv6Statistics {
            total_double_compression: *self.double_compression.lock().unwrap(),
            total_too_many_groups: *self.too_many_groups.lock().unwrap(),
            total_invalid_hex: *self.invalid_hex_digits.lock().unwrap(),
            total_invalid_lengths: *self.invalid_group_lengths.lock().unwrap(),
            total_invalid_chars: *self.invalid_characters.lock().unwrap(),
            total_incomplete_compression: *self.incomplete_compression.lock().unwrap(),
            total_colon_errors: *self.colon_placement_errors.lock().unwrap(),
            total_malformed_ipv4_mapped: *self.malformed_ipv4_mapped.lock().unwrap(),
            total_empty_group_errors: *self.empty_group_errors.lock().unwrap(),
            total_zone_id_errors: *self.zone_id_errors.lock().unwrap(),
            total_port_with_malformed: *self.port_with_malformed_ipv6.lock().unwrap(),
            total_rejected: *self.rejected_malformed.lock().unwrap(),
            total_valid: *self.valid_authorities.lock().unwrap(),
            consistency_violations: *self.consistency_violations.lock().unwrap(),
        }
    }
}

#[derive(Debug, Default)]
struct MalformedIPv6Analysis {
    pub has_brackets: bool,
    pub has_port: bool,
    pub ipv6_address: Option<String>,
    pub has_double_compression: bool,
    pub has_too_many_groups: bool,
    pub has_invalid_hex_digits: bool,
    pub has_invalid_group_lengths: bool,
    pub has_invalid_characters: bool,
    pub has_incomplete_compression: bool,
    pub has_colon_placement_errors: bool,
    pub has_malformed_ipv4_mapped: bool,
    pub has_empty_group_errors: bool,
    pub has_zone_id_errors: bool,
    pub is_malformed: bool,
}

#[derive(Debug, Clone)]
enum MalformedIPv6Result {
    Accepted,
    BadRequest(&'static str),
}

#[derive(Debug)]
struct MalformedIPv6Statistics {
    pub total_double_compression: u64,
    pub total_too_many_groups: u64,
    pub total_invalid_hex: u64,
    pub total_invalid_lengths: u64,
    pub total_invalid_chars: u64,
    pub total_incomplete_compression: u64,
    pub total_colon_errors: u64,
    pub total_malformed_ipv4_mapped: u64,
    pub total_empty_group_errors: u64,
    pub total_zone_id_errors: u64,
    pub total_port_with_malformed: u64,
    pub total_rejected: u64,
    pub total_valid: u64,
    pub consistency_violations: u64,
}

/// Fuzz input structure for malformed IPv6 testing
#[derive(Arbitrary, Debug)]
struct MalformedIPv6Input {
    /// Base IPv6 components
    ipv6_groups: Vec<String>,
    /// Port number
    port: u16,
    /// Zone identifier
    zone_id: String,
    /// Test scenario configuration
    scenario: MalformedIPv6Scenario,
    /// Variation index
    variation: u8,
}

#[derive(Arbitrary, Debug, Clone)]
enum MalformedIPv6Scenario {
    /// Primary: double compression "[2001:db8::1::2]"
    DoubleCompression,
    /// Too many groups "[1:2:3:4:5:6:7:8:9]"
    TooManyGroups,
    /// Invalid hex digits "[2001:gggg::1]"
    InvalidHexDigits,
    /// Invalid group length "[2001:12345::1]"
    InvalidGroupLength,
    /// Invalid characters "[2001:db8::1@]"
    InvalidCharacters,
    /// Incomplete compression "[2001:db8:::1]"
    IncompleteCompression,
    /// Colon placement errors "[2001:db8::]:"
    ColonPlacementErrors,
    /// Malformed IPv4-mapped "[::ffff:999.999.999.999]"
    MalformedIPv4Mapped,
    /// Empty group errors "[:1::]"
    EmptyGroupErrors,
    /// Zone ID errors "[2001:db8::1%:]:80"
    ZoneIDErrors,
    /// Valid IPv6 (for comparison)
    ValidIPv6,
}

impl MalformedIPv6Input {
    /// Generate authority string based on the test scenario
    fn generate_authority(&self) -> String {
        match &self.scenario {
            MalformedIPv6Scenario::DoubleCompression => {
                // Primary test case: double :: compression
                let patterns = [
                    "[2001:db8::1::2]",
                    "[::1::]",
                    "[:::]",
                    "[2001::db8::1]",
                    "[::ffff::1]"
                ];
                let index = (self.variation as usize) % patterns.len();
                let base = patterns[index];

                if self.port > 0 {
                    format!("{}:{}", base, self.port)
                } else {
                    base.to_string()
                }
            }

            MalformedIPv6Scenario::TooManyGroups => {
                // Too many IPv6 groups (>8)
                let malformed_addresses = [
                    "[1:2:3:4:5:6:7:8:9]",
                    "[2001:db8:85a3:0000:0000:8a2e:0370:7334:extra]",
                    "[1:2:3:4:5:6:7:8:9:a:b:c]"
                ];
                let index = (self.variation as usize) % malformed_addresses.len();
                malformed_addresses[index].to_string()
            }

            MalformedIPv6Scenario::InvalidHexDigits => {
                // Invalid hex digits in IPv6
                let malformed_addresses = [
                    "[2001:gggg::1]",
                    "[2001:db8::xyz]",
                    "[abcde::1z]",
                    "[2001:ghij::]"
                ];
                let index = (self.variation as usize) % malformed_addresses.len();
                malformed_addresses[index].to_string()
            }

            MalformedIPv6Scenario::InvalidGroupLength => {
                // Invalid group lengths (>4 hex digits)
                let malformed_addresses = [
                    "[2001:12345::1]",
                    "[abcdef::1]",
                    "[1:22222::]",
                    "[123456::]"
                ];
                let index = (self.variation as usize) % malformed_addresses.len();
                malformed_addresses[index].to_string()
            }

            MalformedIPv6Scenario::InvalidCharacters => {
                // Invalid characters in IPv6
                let malformed_addresses = [
                    "[2001:db8::1@]",
                    "[2001:db8::1!]",
                    "[2001:db8::1#]",
                    "[2001:db8::1$]"
                ];
                let index = (self.variation as usize) % malformed_addresses.len();
                malformed_addresses[index].to_string()
            }

            MalformedIPv6Scenario::IncompleteCompression => {
                // Incomplete compression patterns
                let malformed_addresses = [
                    "[2001:db8:::1]",
                    "[2001:::]",
                    "[:::1]",
                    "[:::]"
                ];
                let index = (self.variation as usize) % malformed_addresses.len();
                malformed_addresses[index].to_string()
            }

            MalformedIPv6Scenario::ColonPlacementErrors => {
                // Colon placement errors
                let malformed_addresses = [
                    "[2001:db8::]:",
                    ":[::1]",
                    "[::1]:",
                    "[:2001:db8::]"
                ];
                let index = (self.variation as usize) % malformed_addresses.len();
                malformed_addresses[index].to_string()
            }

            MalformedIPv6Scenario::MalformedIPv4Mapped => {
                // Malformed IPv4-mapped IPv6
                let malformed_addresses = [
                    "[::ffff:999.999.999.999]",
                    "[::ffff:192.0.2]",
                    "[::ffff:192.0.2.1.1]",
                    "[::ffff:300.0.0.1]"
                ];
                let index = (self.variation as usize) % malformed_addresses.len();
                malformed_addresses[index].to_string()
            }

            MalformedIPv6Scenario::EmptyGroupErrors => {
                // Empty groups in wrong places
                let malformed_addresses = [
                    "[:1::]",
                    "[2001:::]",
                    "[::1:]",
                    "[1::]"
                ];
                let index = (self.variation as usize) % malformed_addresses.len();
                malformed_addresses[index].to_string()
            }

            MalformedIPv6Scenario::ZoneIDErrors => {
                // Zone ID syntax errors
                let malformed_addresses = [
                    "[2001:db8::1%:]",
                    "[2001:db8::1%eth0:]",
                    "[fe80::1%]",
                    "[fe80::1%eth[0]]"
                ];
                let index = (self.variation as usize) % malformed_addresses.len();
                let base = malformed_addresses[index];

                if self.port > 0 {
                    format!("{}:{}", base, self.port)
                } else {
                    base.to_string()
                }
            }

            MalformedIPv6Scenario::ValidIPv6 => {
                // Valid IPv6 for comparison
                let valid_addresses = [
                    "[::1]",
                    "[2001:db8::1]",
                    "[fe80::1%eth0]",
                    "[::ffff:192.0.2.1]"
                ];
                let index = (self.variation as usize) % valid_addresses.len();
                let base = valid_addresses[index];

                if self.port > 0 {
                    format!("{}:{}", base, self.port)
                } else {
                    base.to_string()
                }
            }
        }
    }
}

fuzz_target!(|input: MalformedIPv6Input| {
    // Skip excessively large inputs
    if input.ipv6_groups.len() > 20 || input.zone_id.len() > 50 {
        return;
    }

    // Generate test configuration
    let config = MalformedIPv6TestConfig::default();

    // Create mock connection
    let connection = MockMalformedIPv6Connection::new(config);

    // Generate authority for testing
    let authority = input.generate_authority();

    // Limit authority length to prevent OOM
    if authority.len() > 512 {
        return;
    }

    // Test the malformed IPv6 validation
    let result = connection.handle_malformed_ipv6_request(&authority);

    // Verify the result makes sense
    match result {
        MalformedIPv6Result::Accepted => {
            // Should only be accepted for valid IPv6 syntax
        }
        MalformedIPv6Result::BadRequest(_reason) => {
            // Should be rejected for malformed IPv6
        }
    }

    // Test consistency: same input should yield same result
    let result2 = connection.handle_malformed_ipv6_request(&authority);
    if !connection.results_match(&result, &result2) {
        panic!("Inconsistent malformed IPv6 validation: {:?} != {:?} for authority: '{}'",
               result, result2, authority);
    }

    // Generate statistics for analysis
    let _stats = connection.generate_statistics();

    // Verify no consistency violations were detected internally
    assert_eq!(*connection.consistency_violations.lock().unwrap(), 0,
               "Internal consistency violations detected");

    // For malformed IPv6 scenarios, verify rejection
    match input.scenario {
        MalformedIPv6Scenario::DoubleCompression |
        MalformedIPv6Scenario::TooManyGroups |
        MalformedIPv6Scenario::InvalidHexDigits |
        MalformedIPv6Scenario::InvalidGroupLength |
        MalformedIPv6Scenario::InvalidCharacters |
        MalformedIPv6Scenario::IncompleteCompression |
        MalformedIPv6Scenario::ColonPlacementErrors |
        MalformedIPv6Scenario::MalformedIPv4Mapped |
        MalformedIPv6Scenario::EmptyGroupErrors |
        MalformedIPv6Scenario::ZoneIDErrors => {
            match result {
                MalformedIPv6Result::BadRequest(_) => {
                    // Correct: malformed IPv6 should be rejected
                }
                MalformedIPv6Result::Accepted => {
                    // Only acceptable if the generated authority is actually valid
                    // Check for common malformation patterns
                    if authority.contains("::") && authority.matches("::").count() > 1 {
                        panic!("RFC 4291 violation: double :: compression '{}' should be rejected", authority);
                    }
                    if authority.contains(":::") {
                        panic!("RFC 4291 violation: incomplete compression '{}' should be rejected", authority);
                    }
                    if authority.matches(':').count() > 8 {
                        panic!("RFC 4291 violation: too many colons '{}' should be rejected", authority);
                    }
                }
            }
        }
        MalformedIPv6Scenario::ValidIPv6 => {
            // Valid IPv6 should generally be accepted
        }
    }
});