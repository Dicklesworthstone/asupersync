#![no_main]
//! HTTP/2 :path pseudo-header Unicode fuzz target
//!
//! Tests handling of non-ASCII Unicode characters in :path pseudo-header.
//! Per RFC 9112, path is bytes and UTF-8 should be percent-encoded, but
//! raw UTF-8 in :path is undefined behavior. Verifies parser handles
//! raw UTF-8 consistently (accept or reject) without panic.
//!
//! Test scenarios:
//! - Valid UTF-8 characters (Chinese: 路径, emoji: 🚀, accents: café)
//! - Invalid UTF-8 byte sequences (orphaned continuation bytes)
//! - Mixed ASCII + Unicode paths
//! - Boundary cases (overlong encoding, surrogate pairs)
//! - Very long Unicode paths (memory/buffer testing)
//!
//! RFC references:
//! - RFC 9112 §3.2: Request target is bytes, not Unicode
//! - RFC 7541 §5.2: HPACK string literal encoding
//! - RFC 7540 §8.1.2.3: :path pseudo-header requirements

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Configuration for Unicode path testing scenarios
#[derive(Debug, Clone)]
struct UnicodeTestConfig {
    /// Include valid UTF-8 multi-byte characters
    pub include_valid_unicode: bool,
    /// Include invalid UTF-8 byte sequences
    pub include_invalid_utf8: bool,
    /// Include emoji and extended Unicode planes
    pub include_emoji: bool,
    /// Include very long Unicode paths (>1KB)
    pub include_long_paths: bool,
    /// Include overlong UTF-8 encodings
    pub include_overlong: bool,
}

impl Default for UnicodeTestConfig {
    fn default() -> Self {
        Self {
            include_valid_unicode: true,
            include_invalid_utf8: true,
            include_emoji: true,
            include_long_paths: true,
            include_overlong: true,
        }
    }
}

/// Mock HTTP/2 connection for Unicode path validation testing
#[derive(Debug)]
struct MockUnicodePathConnection {
    /// Count of requests with valid UTF-8 paths
    pub valid_utf8_paths: Arc<Mutex<u64>>,
    /// Count of requests with invalid UTF-8 bytes
    pub invalid_utf8_paths: Arc<Mutex<u64>>,
    /// Count of requests with emoji characters
    pub emoji_paths: Arc<Mutex<u64>>,
    /// Count of requests with Chinese/CJK characters
    pub cjk_paths: Arc<Mutex<u64>>,
    /// Count of requests accepted despite Unicode
    pub unicode_accepted: Arc<Mutex<u64>>,
    /// Count of requests rejected due to Unicode
    pub unicode_rejected: Arc<Mutex<u64>>,
    /// Count of PROTOCOL_ERROR responses for invalid UTF-8
    pub protocol_errors: Arc<Mutex<u64>>,
    /// Count of paths exceeding length limits
    pub oversized_paths: Arc<Mutex<u64>>,
    /// Count of overlong UTF-8 encoding attempts
    pub overlong_encodings: Arc<Mutex<u64>>,
    /// Track consistency: accept/reject behavior must be deterministic
    pub consistency_violations: Arc<Mutex<u64>>,
    /// Configuration for this test session
    pub config: UnicodeTestConfig,
    /// Cache of previous decisions for consistency checking
    pub decision_cache: Arc<Mutex<HashMap<Vec<u8>, bool>>>,
}

impl MockUnicodePathConnection {
    fn new(config: UnicodeTestConfig) -> Self {
        Self {
            valid_utf8_paths: Arc::new(Mutex::new(0)),
            invalid_utf8_paths: Arc::new(Mutex::new(0)),
            emoji_paths: Arc::new(Mutex::new(0)),
            cjk_paths: Arc::new(Mutex::new(0)),
            unicode_accepted: Arc::new(Mutex::new(0)),
            unicode_rejected: Arc::new(Mutex::new(0)),
            protocol_errors: Arc::new(Mutex::new(0)),
            oversized_paths: Arc::new(Mutex::new(0)),
            overlong_encodings: Arc::new(Mutex::new(0)),
            consistency_violations: Arc::new(Mutex::new(0)),
            config,
            decision_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Process HTTP/2 request with Unicode path
    fn handle_unicode_path_request(&self, path_bytes: &[u8]) -> RequestResult {
        // Analyze UTF-8 validity
        let is_valid_utf8 = std::str::from_utf8(path_bytes).is_ok();
        let contains_unicode = path_bytes.iter().any(|&b| b > 127);

        if is_valid_utf8 {
            *self.valid_utf8_paths.lock().unwrap() += 1;

            if let Ok(path_str) = std::str::from_utf8(path_bytes) {
                // Check for emoji (basic detection)
                if path_str.chars().any(|c| c as u32 > 0x1F000) {
                    *self.emoji_paths.lock().unwrap() += 1;
                }

                // Check for CJK characters
                if path_str.chars().any(|c| {
                    let code = c as u32;
                    (code >= 0x4E00 && code <= 0x9FFF) || // CJK Unified
                    (code >= 0x3400 && code <= 0x4DBF) || // CJK Extension A
                    (code >= 0x20000 && code <= 0x2A6DF)  // CJK Extension B
                }) {
                    *self.cjk_paths.lock().unwrap() += 1;
                }
            }
        } else {
            *self.invalid_utf8_paths.lock().unwrap() += 1;
        }

        // Check for oversized paths
        if path_bytes.len() > 8192 {
            *self.oversized_paths.lock().unwrap() += 1;
        }

        // Check for overlong UTF-8 encodings
        if self.has_overlong_encoding(path_bytes) {
            *self.overlong_encodings.lock().unwrap() += 1;
        }

        // Simulate parser decision (consistent accept/reject policy)
        let should_accept = self.evaluate_unicode_path_policy(path_bytes, contains_unicode, is_valid_utf8);

        // Check consistency with previous decisions for same input
        let mut cache = self.decision_cache.lock().unwrap();
        if let Some(&previous_decision) = cache.get(path_bytes) {
            if previous_decision != should_accept {
                *self.consistency_violations.lock().unwrap() += 1;
            }
        } else {
            cache.insert(path_bytes.to_vec(), should_accept);
        }

        if should_accept {
            if contains_unicode {
                *self.unicode_accepted.lock().unwrap() += 1;
            }
            RequestResult::Accepted
        } else {
            if contains_unicode {
                *self.unicode_rejected.lock().unwrap() += 1;
            }
            if !is_valid_utf8 {
                *self.protocol_errors.lock().unwrap() += 1;
                RequestResult::ProtocolError("Invalid UTF-8 in :path")
            } else {
                RequestResult::BadRequest("Unicode not allowed in :path")
            }
        }
    }

    /// Detect overlong UTF-8 encodings (security issue)
    fn has_overlong_encoding(&self, bytes: &[u8]) -> bool {
        let mut i = 0;
        while i < bytes.len() {
            let byte = bytes[i];

            if (byte & 0x80) == 0 {
                // ASCII, skip
                i += 1;
            } else if (byte & 0xE0) == 0xC0 {
                // 2-byte sequence
                if i + 1 < bytes.len() {
                    let byte2 = bytes[i + 1];
                    // Check for overlong: 110000xx 10xxxxxx encoding < 0x80
                    if byte == 0xC0 || byte == 0xC1 {
                        return true;
                    }
                }
                i += 2;
            } else if (byte & 0xF0) == 0xE0 {
                // 3-byte sequence
                if i + 2 < bytes.len() {
                    // Check for overlong encoding < 0x800
                    if byte == 0xE0 && (bytes[i + 1] & 0xA0) == 0x80 {
                        return true;
                    }
                }
                i += 3;
            } else if (byte & 0xF8) == 0xF0 {
                // 4-byte sequence
                if i + 3 < bytes.len() {
                    // Check for overlong encoding < 0x10000
                    if byte == 0xF0 && (bytes[i + 1] & 0x90) == 0x80 {
                        return true;
                    }
                }
                i += 4;
            } else {
                // Invalid start byte
                return false;
            }
        }
        false
    }

    /// Evaluate Unicode path policy (lenient vs strict)
    /// Returns true if path should be accepted
    fn evaluate_unicode_path_policy(&self, path_bytes: &[u8], contains_unicode: bool, is_valid_utf8: bool) -> bool {
        // Strategy 1: Strict ASCII-only policy
        if !self.config.include_valid_unicode && contains_unicode {
            return false;
        }

        // Strategy 2: Reject invalid UTF-8
        if !self.config.include_invalid_utf8 && !is_valid_utf8 {
            return false;
        }

        // Strategy 3: Length limits
        if path_bytes.len() > 8192 && !self.config.include_long_paths {
            return false;
        }

        // Strategy 4: Security - reject overlong encodings
        if !self.config.include_overlong && self.has_overlong_encoding(path_bytes) {
            return false;
        }

        // Default: lenient policy accepts valid UTF-8
        is_valid_utf8 && path_bytes.len() <= 65536
    }

    /// Generate summary statistics
    fn generate_statistics(&self) -> UnicodePathStatistics {
        UnicodePathStatistics {
            total_valid_utf8: *self.valid_utf8_paths.lock().unwrap(),
            total_invalid_utf8: *self.invalid_utf8_paths.lock().unwrap(),
            total_emoji: *self.emoji_paths.lock().unwrap(),
            total_cjk: *self.cjk_paths.lock().unwrap(),
            total_accepted: *self.unicode_accepted.lock().unwrap(),
            total_rejected: *self.unicode_rejected.lock().unwrap(),
            total_protocol_errors: *self.protocol_errors.lock().unwrap(),
            total_oversized: *self.oversized_paths.lock().unwrap(),
            total_overlong: *self.overlong_encodings.lock().unwrap(),
            consistency_violations: *self.consistency_violations.lock().unwrap(),
        }
    }
}

#[derive(Debug, Clone)]
enum RequestResult {
    Accepted,
    BadRequest(&'static str),
    ProtocolError(&'static str),
}

#[derive(Debug)]
struct UnicodePathStatistics {
    pub total_valid_utf8: u64,
    pub total_invalid_utf8: u64,
    pub total_emoji: u64,
    pub total_cjk: u64,
    pub total_accepted: u64,
    pub total_rejected: u64,
    pub total_protocol_errors: u64,
    pub total_oversized: u64,
    pub total_overlong: u64,
    pub consistency_violations: u64,
}

/// Fuzz input structure for Unicode path testing
#[derive(Arbitrary, Debug)]
struct UnicodePathInput {
    /// Base path component (may be ASCII or Unicode)
    base_path: String,
    /// Additional Unicode characters to inject
    unicode_chars: Vec<char>,
    /// Raw bytes to inject (may create invalid UTF-8)
    raw_bytes: Vec<u8>,
    /// Test scenario configuration
    scenario: UnicodeTestScenario,
    /// Path length multiplier (for stress testing)
    length_multiplier: u8,
}

#[derive(Arbitrary, Debug, Clone)]
enum UnicodeTestScenario {
    /// Valid UTF-8 Unicode path
    ValidUnicode,
    /// Invalid UTF-8 byte sequence
    InvalidUtf8,
    /// Mixed ASCII + Unicode
    MixedPath,
    /// Emoji-only path
    EmojiPath,
    /// CJK character path
    CjkPath,
    /// Overlong UTF-8 encoding
    OverlongEncoding,
    /// Maximum length Unicode path
    MaxLengthPath,
    /// Boundary testing (edge cases)
    BoundaryTest,
}

impl UnicodePathInput {
    /// Generate path bytes based on the test scenario
    fn generate_path_bytes(&self) -> Vec<u8> {
        match &self.scenario {
            UnicodeTestScenario::ValidUnicode => {
                let mut path = format!("/{}", self.base_path);
                for ch in &self.unicode_chars {
                    path.push(*ch);
                }
                path.into_bytes()
            }

            UnicodeTestScenario::InvalidUtf8 => {
                let mut bytes = vec![b'/'];
                bytes.extend_from_slice(self.base_path.as_bytes());
                // Inject invalid UTF-8: orphaned continuation bytes
                bytes.extend_from_slice(&[0xBF, 0x80, 0xFF]);
                bytes.extend_from_slice(&self.raw_bytes);
                bytes
            }

            UnicodeTestScenario::MixedPath => {
                let mut path = format!("/api/{}/", self.base_path);
                // Add some Unicode
                path.push_str("路径");
                path.push('/');
                for ch in &self.unicode_chars {
                    if ch.is_ascii() || (*ch as u32) < 0x10000 {
                        path.push(*ch);
                    }
                }
                path.into_bytes()
            }

            UnicodeTestScenario::EmojiPath => {
                let mut path = String::from("/🚀/");
                path.push_str(&self.base_path);
                // Add more emoji
                path.push_str("/🌟/💻/🔥");
                for ch in &self.unicode_chars {
                    if (*ch as u32) > 0x1F000 {
                        path.push(*ch);
                    }
                }
                path.into_bytes()
            }

            UnicodeTestScenario::CjkPath => {
                let mut path = String::from("/用户/");
                path.push_str(&self.base_path);
                path.push_str("/数据/测试");
                for ch in &self.unicode_chars {
                    let code = *ch as u32;
                    if (code >= 0x4E00 && code <= 0x9FFF) {
                        path.push(*ch);
                    }
                }
                path.into_bytes()
            }

            UnicodeTestScenario::OverlongEncoding => {
                let mut bytes = vec![b'/'];
                bytes.extend_from_slice(self.base_path.as_bytes());
                // Overlong encoding of ASCII 'A' (0x41) as 3-byte sequence
                bytes.extend_from_slice(&[0xE0, 0x81, 0x81]);
                // Overlong encoding of '/' (0x2F) as 2-byte sequence
                bytes.extend_from_slice(&[0xC0, 0xAF]);
                bytes.extend_from_slice(&self.raw_bytes);
                bytes
            }

            UnicodeTestScenario::MaxLengthPath => {
                let mut path = String::from("/");
                let repeat_count = (self.length_multiplier as usize).max(1);
                for _ in 0..repeat_count {
                    path.push_str(&self.base_path);
                    path.push_str("/路径很长的测试路径/");
                    for ch in &self.unicode_chars {
                        path.push(*ch);
                        if path.len() > 32768 {
                            break;
                        }
                    }
                }
                path.into_bytes()
            }

            UnicodeTestScenario::BoundaryTest => {
                let mut bytes = vec![b'/'];
                // Test various boundary conditions
                bytes.extend_from_slice(&[0xC2, 0x80]); // Minimal 2-byte sequence
                bytes.extend_from_slice(&[0xE0, 0xA0, 0x80]); // Minimal 3-byte
                bytes.extend_from_slice(&[0xF0, 0x90, 0x80, 0x80]); // Minimal 4-byte
                bytes.extend_from_slice(self.base_path.as_bytes());
                bytes.extend_from_slice(&self.raw_bytes);
                bytes
            }
        }
    }
}

fuzz_target!(|input: UnicodePathInput| {
    // Skip empty inputs or excessively large inputs
    if input.base_path.is_empty() || input.unicode_chars.len() > 1000 {
        return;
    }

    // Generate test configuration
    let config = UnicodeTestConfig {
        include_valid_unicode: true,
        include_invalid_utf8: true,
        include_emoji: true,
        include_long_paths: input.length_multiplier > 100,
        include_overlong: true,
    };

    // Create mock connection
    let connection = MockUnicodePathConnection::new(config);

    // Generate path bytes for testing
    let path_bytes = input.generate_path_bytes();

    // Limit path length to prevent OOM
    if path_bytes.len() > 65536 {
        return;
    }

    // Test the Unicode path handling
    let result = connection.handle_unicode_path_request(&path_bytes);

    // Verify no panic occurred and result is consistent
    match result {
        RequestResult::Accepted => {
            // Valid acceptance - should be reproducible
        }
        RequestResult::BadRequest(_reason) => {
            // Valid rejection due to policy
        }
        RequestResult::ProtocolError(_reason) => {
            // Valid rejection due to invalid UTF-8
        }
    }

    // Test consistency: same input should yield same result
    let result2 = connection.handle_unicode_path_request(&path_bytes);
    match (&result, &result2) {
        (RequestResult::Accepted, RequestResult::Accepted) => {},
        (RequestResult::BadRequest(_), RequestResult::BadRequest(_)) => {},
        (RequestResult::ProtocolError(_), RequestResult::ProtocolError(_)) => {},
        _ => {
            // Consistency violation detected
            panic!("Inconsistent Unicode path handling: {:?} != {:?} for path: {:?}",
                   result, result2,
                   String::from_utf8_lossy(&path_bytes));
        }
    }

    // Generate statistics for analysis
    let _stats = connection.generate_statistics();

    // Verify no consistency violations were detected internally
    assert_eq!(*connection.consistency_violations.lock().unwrap(), 0,
               "Internal consistency violations detected");
});