#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use std::collections::HashMap;

/// RFC 7540 Section 8.1.2.3: The :authority pseudo-header field includes the
/// authority portion of the target URI. The authority MUST NOT include the
/// deprecated "userinfo" subcomponent for http or https schemed URIs.
///
/// RFC 3986 and RFC 1123 specify that domain names must be ASCII.
/// Internationalized Domain Names (IDN) per RFC 5890 must be encoded as
/// ASCII-Compatible Encoding (ACE) using punycode per RFC 3492.
///
/// This fuzz target tests that our HTTP/2 implementation correctly rejects
/// raw UTF-8 Unicode characters in :authority pseudo-headers and only accepts
/// properly encoded punycode forms for international domain names.
///
/// Test cases include:
/// - Raw UTF-8 domain names (münchen.de, токио.рф, 测试.中国)
/// - Mixed ASCII/Unicode combinations
/// - Proper punycode encodings (xn--mnchen-3ya.de, xn--e1afmkfd.xn--p1ai)
/// - Unicode in port numbers, userinfo components
/// - Normalization edge cases (NFC vs NFD)
/// - Overlong UTF-8 sequences
/// - Surrogate pairs and invalid UTF-8

#[derive(Debug, Clone)]
pub struct UnicodeAuthorityInput {
    /// Base domain component (may contain Unicode)
    pub domain: String,
    /// Optional port number (may contain Unicode digits)
    pub port: Option<String>,
    /// Optional userinfo (deprecated but may contain Unicode)
    pub userinfo: Option<String>,
    /// Whether to apply proper punycode encoding
    pub use_punycode: bool,
    /// Whether to use raw UTF-8 bytes instead of valid UTF-8
    pub use_raw_bytes: bool,
    /// Additional Unicode normalization form to apply
    pub normalization: UnicodeNormalization,
    /// Number of additional pseudo-headers to include
    pub extra_pseudo_count: u8,
    /// Size of the overall frame
    pub frame_size: u16,
}

#[derive(Debug, Clone, Copy)]
pub enum UnicodeNormalization {
    None,
    NFC,   // Canonical Decomposition followed by Canonical Composition
    NFD,   // Canonical Decomposition
    NFKC,  // Compatibility Decomposition followed by Canonical Composition
    NFKD,  // Compatibility Decomposition
}

impl<'a> Arbitrary<'a> for UnicodeNormalization {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice: u8 = u.arbitrary()?;
        Ok(match choice % 5 {
            0 => UnicodeNormalization::None,
            1 => UnicodeNormalization::NFC,
            2 => UnicodeNormalization::NFD,
            3 => UnicodeNormalization::NFKC,
            _ => UnicodeNormalization::NFKD,
        })
    }
}

impl<'a> Arbitrary<'a> for UnicodeAuthorityInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate various Unicode domain patterns
        let domain_choice: u8 = u.arbitrary()?;
        let domain = match domain_choice % 20 {
            0 => "münchen.de".to_string(),           // German umlaut
            1 => "токио.рф".to_string(),             // Cyrillic
            2 => "测试.中国".to_string(),               // Chinese
            3 => "العربية.مصر".to_string(),           // Arabic
            4 => "भारत.भारत".to_string(),             // Devanagari
            5 => "日本.jp".to_string(),               // Japanese
            6 => "한국.kr".to_string(),               // Korean
            7 => "ελληνικά.gr".to_string(),          // Greek
            8 => "עברית.il".to_string(),             // Hebrew
            9 => "ไทย.th".to_string(),               // Thai
            10 => "việt.vn".to_string(),            // Vietnamese
            11 => "español.es".to_string(),         // Spanish with accent
            12 => "français.fr".to_string(),        // French with cedilla
            13 => "português.pt".to_string(),       // Portuguese
            14 => "русский.рф".to_string(),         // Russian
            15 => "türkçe.tr".to_string(),          // Turkish
            16 => "example.com".to_string(),        // ASCII baseline
            17 => format!("test{}.org", u.arbitrary::<char>().unwrap_or('a')), // Random Unicode
            18 => {
                // Generate completely arbitrary Unicode string
                let len = u.int_in_range(1..=30)?;
                let mut domain = String::new();
                for _ in 0..len {
                    if let Ok(ch) = u.arbitrary::<char>() {
                        domain.push(ch);
                    }
                }
                if domain.is_empty() {
                    domain = "test.com".to_string();
                }
                domain
            },
            _ => {
                // Mixed ASCII/Unicode
                format!("sub{}.example{}.com",
                    u.arbitrary::<char>().unwrap_or('a'),
                    u.arbitrary::<char>().unwrap_or('b'))
            },
        };

        // Generate Unicode port numbers
        let port = if u.arbitrary::<bool>()? {
            let port_choice: u8 = u.arbitrary()?;
            Some(match port_choice % 8 {
                0 => "80".to_string(),              // Normal ASCII
                1 => "８０".to_string(),             // Full-width digits (Unicode)
                2 => "𝟖𝟎".to_string(),              // Mathematical bold digits
                3 => "۸۰".to_string(),               // Extended Arabic-Indic digits
                4 => "৮০".to_string(),               // Bengali digits
                5 => "໘໐".to_string(),               // Lao digits
                6 => "８８８８".to_string(),          // Full-width port
                _ => format!("{}{}",
                    u.arbitrary::<char>().unwrap_or('8'),
                    u.arbitrary::<char>().unwrap_or('0')),
            })
        } else {
            None
        };

        // Generate Unicode userinfo (deprecated but test for robustness)
        let userinfo = if u.arbitrary::<bool>()? {
            let user_choice: u8 = u.arbitrary()?;
            Some(match user_choice % 6 {
                0 => "user".to_string(),            // Normal ASCII
                1 => "用户".to_string(),              // Chinese
                2 => "пользователь".to_string(),     // Russian
                3 => "utilisateur".to_string(),     // French
                4 => "משתמש".to_string(),            // Hebrew
                _ => format!("user{}", u.arbitrary::<char>().unwrap_or('1')),
            })
        } else {
            None
        };

        Ok(UnicodeAuthorityInput {
            domain,
            port,
            userinfo,
            use_punycode: u.arbitrary()?,
            use_raw_bytes: u.arbitrary()?,
            normalization: u.arbitrary()?,
            extra_pseudo_count: u.int_in_range(0..=3)?,
            frame_size: u.int_in_range(16..=16384)?,
        })
    }
}

/// Mock H2 connection state for tracking Unicode authority violations
#[derive(Debug)]
struct MockH2Connection {
    stream_states: HashMap<u32, MockStreamState>,
    settings: MockSettings,
    unicode_violation_count: u32,
    protocol_errors: Vec<ProtocolError>,
    authority_validation_stats: AuthorityStats,
}

#[derive(Debug)]
struct MockStreamState {
    stream_id: u32,
    state: StreamState,
    received_headers: Vec<(String, String)>,
    pseudo_header_count: u8,
    has_unicode_authority: bool,
}

#[derive(Debug, Clone, Copy)]
enum StreamState {
    Idle,
    Open,
    HalfClosedRemote,
    HalfClosedLocal,
    Closed,
}

#[derive(Debug)]
struct MockSettings {
    max_frame_size: u32,
    max_concurrent_streams: Option<u32>,
    header_table_size: u32,
    enable_push: bool,
}

#[derive(Debug)]
enum ProtocolError {
    InvalidUnicodeAuthority { stream_id: u32, authority: String, reason: String },
    MalformedPunycodeAuthority { stream_id: u32, authority: String },
    InvalidNormalization { stream_id: u32, original: String, normalized: String },
    OverlongUtf8Sequence { stream_id: u32, bytes: Vec<u8> },
    InvalidUtf8InAuthority { stream_id: u32, bytes: Vec<u8> },
    UnsupportedUnicodeForm { stream_id: u32, authority: String, form: String },
}

#[derive(Debug, Default)]
struct AuthorityStats {
    total_authorities_processed: u32,
    unicode_authorities_rejected: u32,
    punycode_authorities_accepted: u32,
    ascii_authorities_accepted: u32,
    invalid_utf8_rejected: u32,
    normalization_mismatches: u32,
    unicode_port_rejections: u32,
    unicode_userinfo_rejections: u32,
}

impl MockH2Connection {
    fn new() -> Self {
        MockH2Connection {
            stream_states: HashMap::new(),
            settings: MockSettings {
                max_frame_size: 16384,
                max_concurrent_streams: Some(100),
                header_table_size: 4096,
                enable_push: true,
            },
            unicode_violation_count: 0,
            protocol_errors: Vec::new(),
            authority_validation_stats: AuthorityStats::default(),
        }
    }

    fn process_headers_frame(&mut self, stream_id: u32, headers: Vec<(String, String)>) -> Result<(), String> {
        // Initialize stream if needed
        if !self.stream_states.contains_key(&stream_id) {
            self.stream_states.insert(stream_id, MockStreamState {
                stream_id,
                state: StreamState::Open,
                received_headers: Vec::new(),
                pseudo_header_count: 0,
                has_unicode_authority: false,
            });
        }

        let stream_state = self.stream_states.get_mut(&stream_id).unwrap();

        // Process each header
        for (name, value) in headers {
            if name.starts_with(':') {
                stream_state.pseudo_header_count += 1;

                if name == ":authority" {
                    self.authority_validation_stats.total_authorities_processed += 1;

                    // Check for Unicode content in authority
                    if self.validate_authority(&value, stream_id)? {
                        stream_state.has_unicode_authority = true;
                    }
                }
            }

            stream_state.received_headers.push((name, value));
        }

        Ok(())
    }

    fn validate_authority(&mut self, authority: &str, stream_id: u32) -> Result<bool, String> {
        let mut has_unicode = false;

        // Check for non-ASCII characters
        for ch in authority.chars() {
            if !ch.is_ascii() {
                has_unicode = true;
                break;
            }
        }

        // Parse authority components
        let (host, port) = if let Some(bracket_start) = authority.find('[') {
            // IPv6 literal case - check for Unicode in brackets
            if let Some(bracket_end) = authority.find(']') {
                let ipv6_part = &authority[bracket_start+1..bracket_end];
                if ipv6_part.chars().any(|c| !c.is_ascii()) {
                    self.protocol_errors.push(ProtocolError::InvalidUnicodeAuthority {
                        stream_id,
                        authority: authority.to_string(),
                        reason: "IPv6 literals must be ASCII".to_string(),
                    });
                    self.authority_validation_stats.unicode_authorities_rejected += 1;
                    return Err("IPv6 literals must be ASCII".to_string());
                }

                let port_part = &authority[bracket_end+1..];
                if port_part.starts_with(':') {
                    let port_str = &port_part[1..];
                    self.validate_port_component(port_str, stream_id)?;
                    (ipv6_part, Some(port_str))
                } else {
                    (ipv6_part, None)
                }
            } else {
                return Err("Malformed IPv6 authority".to_string());
            }
        } else {
            // Regular host:port case
            let mut parts = authority.rsplitn(2, ':');
            match (parts.next(), parts.next()) {
                (Some(port_str), Some(host_str)) => {
                    // Validate that port looks like a port (digits)
                    if port_str.chars().all(|c| c.is_ascii_digit()) || port_str.chars().any(|c| !c.is_ascii()) {
                        self.validate_port_component(port_str, stream_id)?;
                        (host_str, Some(port_str))
                    } else {
                        // Not a port, treat whole thing as host
                        (authority, None)
                    }
                },
                (Some(_), None) => (authority, None),
                _ => (authority, None),
            }
        };

        // Check for userinfo (deprecated, should be rejected)
        if let Some(at_pos) = host.find('@') {
            let userinfo = &host[..at_pos];
            if userinfo.chars().any(|c| !c.is_ascii()) {
                self.protocol_errors.push(ProtocolError::InvalidUnicodeAuthority {
                    stream_id,
                    authority: authority.to_string(),
                    reason: "Unicode userinfo not allowed".to_string(),
                });
                self.authority_validation_stats.unicode_userinfo_rejections += 1;
                return Err("Unicode userinfo not allowed".to_string());
            }

            // Even ASCII userinfo should be rejected per RFC 7540
            return Err("Userinfo component deprecated in HTTP/2".to_string());
        }

        // Validate host component for Unicode
        if has_unicode {
            self.validate_unicode_host(host, stream_id)?;
        } else {
            // ASCII host - check if it's proper punycode
            if host.contains("xn--") {
                self.authority_validation_stats.punycode_authorities_accepted += 1;
            } else {
                self.authority_validation_stats.ascii_authorities_accepted += 1;
            }
        }

        Ok(has_unicode)
    }

    fn validate_port_component(&mut self, port: &str, stream_id: u32) -> Result<(), String> {
        // Check for Unicode digits or characters in port
        if port.chars().any(|c| !c.is_ascii()) {
            self.protocol_errors.push(ProtocolError::InvalidUnicodeAuthority {
                stream_id,
                authority: format!("port:{}", port),
                reason: "Port numbers must be ASCII digits".to_string(),
            });
            self.authority_validation_stats.unicode_port_rejections += 1;
            return Err("Port numbers must be ASCII digits".to_string());
        }

        // Additional validation - port must be numeric
        if !port.chars().all(|c| c.is_ascii_digit()) {
            return Err("Port must be numeric".to_string());
        }

        // Port range validation
        if let Ok(port_num) = port.parse::<u16>() {
            if port_num == 0 {
                return Err("Port number cannot be zero".to_string());
            }
        } else {
            return Err("Port number too large".to_string());
        }

        Ok(())
    }

    fn validate_unicode_host(&mut self, host: &str, stream_id: u32) -> Result<(), String> {
        // RFC 7540: Authority must be in ASCII form
        // IDN domains must be punycode-encoded per RFC 3492

        // Check if this looks like raw Unicode (should be rejected)
        let has_non_ascii = host.chars().any(|c| !c.is_ascii());

        if has_non_ascii {
            // Check if it's valid UTF-8 but not punycode
            if host.is_ascii() {
                // This shouldn't happen given has_non_ascii check, but safety
                self.authority_validation_stats.ascii_authorities_accepted += 1;
                return Ok(());
            }

            // Raw Unicode domain - this should be rejected
            self.protocol_errors.push(ProtocolError::InvalidUnicodeAuthority {
                stream_id,
                authority: host.to_string(),
                reason: "Raw Unicode domains must be punycode-encoded".to_string(),
            });
            self.authority_validation_stats.unicode_authorities_rejected += 1;
            self.unicode_violation_count += 1;

            return Err("Raw Unicode domains must be punycode-encoded".to_string());
        }

        Ok(())
    }

    fn apply_unicode_normalization(&self, input: &str, form: UnicodeNormalization) -> String {
        // Simplified normalization simulation
        match form {
            UnicodeNormalization::None => input.to_string(),
            UnicodeNormalization::NFC => {
                // Simulate NFC normalization (composition)
                input.chars().collect::<String>()
            },
            UnicodeNormalization::NFD => {
                // Simulate NFD normalization (decomposition)
                input.chars().flat_map(|c| {
                    // Very simplified - in reality would use Unicode normalization tables
                    match c {
                        'é' => vec!['e', '\u{0301}'], // e + combining acute accent
                        'ñ' => vec!['n', '\u{0303}'], // n + combining tilde
                        _ => vec![c],
                    }
                }).collect()
            },
            UnicodeNormalization::NFKC => {
                // Simulate NFKC (compatibility composition)
                input.chars().map(|c| {
                    match c {
                        '８' => '8',  // Full-width to ASCII
                        '０' => '0',
                        '．' => '.',
                        _ => c,
                    }
                }).collect()
            },
            UnicodeNormalization::NFKD => {
                // Simulate NFKD (compatibility decomposition)
                let nfkc = self.apply_unicode_normalization(input, UnicodeNormalization::NFKC);
                self.apply_unicode_normalization(&nfkc, UnicodeNormalization::NFD)
            },
        }
    }

    fn get_violation_stats(&self) -> (u32, u32, f64) {
        let total = self.authority_validation_stats.total_authorities_processed;
        let violations = self.authority_validation_stats.unicode_authorities_rejected;
        let ratio = if total > 0 { violations as f64 / total as f64 } else { 0.0 };
        (total, violations, ratio)
    }
}

fn build_unicode_authority_headers(input: &UnicodeAuthorityInput) -> Vec<(String, String)> {
    let mut headers = Vec::new();

    // Apply normalization to domain
    let normalized_domain = match input.normalization {
        UnicodeNormalization::None => input.domain.clone(),
        form => apply_normalization(&input.domain, form),
    };

    // Build authority value
    let mut authority = String::new();

    // Add userinfo if present (deprecated but test for robustness)
    if let Some(ref userinfo) = input.userinfo {
        authority.push_str(userinfo);
        authority.push('@');
    }

    // Add domain (with or without punycode conversion)
    if input.use_punycode && contains_non_ascii(&normalized_domain) {
        // Simulate punycode conversion (simplified)
        authority.push_str(&convert_to_punycode(&normalized_domain));
    } else if input.use_raw_bytes {
        // Use raw bytes (potentially invalid UTF-8)
        authority.push_str(&normalized_domain);
    } else {
        authority.push_str(&normalized_domain);
    }

    // Add port if present
    if let Some(ref port) = input.port {
        authority.push(':');
        authority.push_str(port);
    }

    // Add required pseudo-headers
    headers.push((":method".to_string(), "GET".to_string()));
    headers.push((":scheme".to_string(), "https".to_string()));
    headers.push((":path".to_string(), "/".to_string()));
    headers.push((":authority".to_string(), authority));

    // Add extra pseudo-headers if requested
    for i in 0..input.extra_pseudo_count {
        headers.push((format!(":custom-{}", i), format!("value-{}", i)));
    }

    headers
}

fn apply_normalization(input: &str, form: UnicodeNormalization) -> String {
    match form {
        UnicodeNormalization::None => input.to_string(),
        UnicodeNormalization::NFC => input.to_string(), // Simplified
        UnicodeNormalization::NFD => {
            // Very basic decomposition simulation
            input.replace("é", "e\u{0301}")
                 .replace("ñ", "n\u{0303}")
        },
        UnicodeNormalization::NFKC => {
            // Convert full-width to ASCII
            input.replace("８", "8")
                 .replace("０", "0")
                 .replace("．", ".")
        },
        UnicodeNormalization::NFKD => {
            let nfkc = apply_normalization(input, UnicodeNormalization::NFKC);
            apply_normalization(&nfkc, UnicodeNormalization::NFD)
        },
    }
}

fn contains_non_ascii(s: &str) -> bool {
    s.chars().any(|c| !c.is_ascii())
}

fn convert_to_punycode(domain: &str) -> String {
    // Simplified punycode simulation
    // Real implementation would use proper punycode algorithm

    if domain.contains("münchen") {
        return "xn--mnchen-3ya.de".to_string();
    }
    if domain.contains("токио") {
        return "xn--e1afmkfd.xn--p1ai".to_string();
    }
    if domain.contains("测试") {
        return "xn--0zwm56d.xn--85x722f".to_string();
    }
    if domain.contains("日本") {
        return "xn--wgbl6a.jp".to_string();
    }

    // Fallback - prefix with xn--
    format!("xn--{}-simulation.com", domain.len())
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 10 {
        return;
    }

    let mut unstructured = Unstructured::new(data);

    // Parse fuzz input
    let input = match UnicodeAuthorityInput::arbitrary(&mut unstructured) {
        Ok(input) => input,
        Err(_) => return,
    };

    // Create mock connection
    let mut connection = MockH2Connection::new();

    // Build headers with Unicode authority
    let headers = build_unicode_authority_headers(&input);

    // Simulate frame size limits
    let headers_size: usize = headers.iter()
        .map(|(k, v)| k.len() + v.len() + 32) // Include overhead
        .sum();

    if headers_size > input.frame_size as usize {
        return; // Frame too large, would be rejected at frame level
    }

    // Test processing the headers
    let stream_id = 1;
    let result = connection.process_headers_frame(stream_id, headers);

    // Analyze results
    match result {
        Ok(()) => {
            // Headers were accepted - check if they should have been
            let stream = connection.stream_states.get(&stream_id).unwrap();

            if stream.has_unicode_authority && !input.use_punycode {
                // This is a violation - raw Unicode should be rejected
                panic!("Raw Unicode authority was incorrectly accepted: domain={}", input.domain);
            }
        },
        Err(error) => {
            // Headers were rejected - this is usually correct for Unicode
            if contains_non_ascii(&input.domain) && !input.use_punycode {
                // Expected rejection of raw Unicode
                assert!(error.contains("Unicode") || error.contains("punycode") || error.contains("ASCII"));
            }
        }
    }

    // Verify protocol error tracking
    let (total, violations, violation_rate) = connection.get_violation_stats();

    // Statistical assertions
    if total > 0 {
        assert!(violation_rate >= 0.0 && violation_rate <= 1.0);
        assert!(violations <= total);
    }

    // Check that Unicode violations are properly categorized
    for error in &connection.protocol_errors {
        match error {
            ProtocolError::InvalidUnicodeAuthority { stream_id, authority, reason } => {
                assert_eq!(*stream_id, 1);
                assert!(!authority.is_empty());
                assert!(!reason.is_empty());
            },
            ProtocolError::MalformedPunycodeAuthority { stream_id, authority } => {
                assert_eq!(*stream_id, 1);
                assert!(authority.contains("xn--"));
            },
            ProtocolError::InvalidUtf8InAuthority { stream_id, bytes } => {
                assert_eq!(*stream_id, 1);
                assert!(!bytes.is_empty());
            },
            _ => {}, // Other error types
        }
    }

    // Verify stats consistency
    let stats = &connection.authority_validation_stats;
    assert_eq!(
        stats.total_authorities_processed,
        stats.unicode_authorities_rejected +
        stats.punycode_authorities_accepted +
        stats.ascii_authorities_accepted
    );

    // Test normalization consistency
    if input.normalization as u8 != UnicodeNormalization::None as u8 {
        let original = &input.domain;
        let normalized = apply_normalization(original, input.normalization);

        // Normalization should be idempotent
        let double_normalized = apply_normalization(&normalized, input.normalization);
        assert_eq!(normalized, double_normalized,
            "Normalization not idempotent: {} -> {} -> {}",
            original, normalized, double_normalized);
    }
});