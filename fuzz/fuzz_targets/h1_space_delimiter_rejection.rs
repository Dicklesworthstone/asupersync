//! Focused fuzzer for HTTP/1.1 multi-space delimiter rejection
//!
//! This fuzzer specifically targets the recently tightened multi-space delimiter
//! rejection logic in src/http/h1/codec.rs::consume_single_space(). It exercises
//! the exact boundary condition where parse_request_line_bytes_slow rejects
//! multiple consecutive spaces between HTTP tokens.
//!
//! Target coverage:
//! - METHOD SP URI SP VERSION with varying space counts
//! - Space vs tab vs mixed whitespace edge cases
//! - Boundary conditions: 1 space (valid) vs 2+ spaces (rejected)
//! - Tab character injection in space positions
//! - Leading/trailing space variations
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run h1_space_delimiter_rejection
//! ```

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::codec::{Http1Codec, HttpError};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_SIZE: usize = 1024;

/// Space delimiter test specification
#[derive(Arbitrary, Debug)]
struct SpaceDelimiterFuzz {
    /// HTTP method (kept simple for focus)
    method: SimpleMethod,
    /// URI (kept simple for focus)
    uri: SimpleUri,
    /// HTTP version (kept simple for focus)
    version: SimpleVersion,
    /// The key test: space delimiter configurations
    space_config: SpaceDelimiterConfig,
}

#[derive(Arbitrary, Debug)]
enum SimpleMethod {
    Get,
    Post,
    Custom(String),
}

impl SimpleMethod {
    fn as_str(&self) -> &str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Custom(s) => s,
        }
    }
}

#[derive(Arbitrary, Debug)]
enum SimpleUri {
    Root,
    Simple(String),
}

impl SimpleUri {
    fn as_str(&self) -> &str {
        match self {
            Self::Root => "/",
            Self::Simple(s) => s,
        }
    }
}

#[derive(Arbitrary, Debug)]
enum SimpleVersion {
    Http10,
    Http11,
}

impl SimpleVersion {
    fn as_str(&self) -> &str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
        }
    }
}

/// The core space delimiter configuration being tested
#[derive(Arbitrary, Debug)]
struct SpaceDelimiterConfig {
    /// Spaces between method and URI
    method_uri_spaces: SpacePattern,
    /// Spaces between URI and version
    uri_version_spaces: SpacePattern,
    /// Leading spaces before method (should be rejected)
    leading_spaces: u8,
    /// Trailing spaces after version (should be rejected)
    trailing_spaces: u8,
}

/// Specific space patterns to test the delimiter rejection logic
#[derive(Arbitrary, Debug)]
enum SpacePattern {
    /// Single space (should work)
    Single,
    /// Multiple spaces (should be rejected by consume_single_space)
    Multiple(u8),
    /// Tab character (should be rejected)
    Tab,
    /// Mixed space and tab (should be rejected)
    Mixed { spaces: u8, tabs: u8 },
    /// No spaces (should be rejected - missing delimiter)
    None,
    /// Single tab only (should be rejected)
    TabOnly,
}

impl SpacePattern {
    fn generate_bytes(&self) -> Vec<u8> {
        match self {
            Self::Single => vec![b' '],
            Self::Multiple(count) => {
                let count = (*count).clamp(2, 10); // 2-10 spaces
                vec![b' '; count as usize]
            }
            Self::Tab => vec![b'\t'],
            Self::Mixed { spaces, tabs } => {
                let mut result = Vec::new();
                result.extend(vec![b' '; (*spaces).min(5) as usize]);
                result.extend(vec![b'\t'; (*tabs).min(5) as usize]);
                result
            }
            Self::None => Vec::new(),
            Self::TabOnly => vec![b'\t'],
        }
    }

    fn should_be_rejected(&self) -> bool {
        match self {
            Self::Single => false,      // Single space is valid
            Self::Multiple(_) => true,  // Multiple spaces should be rejected
            Self::Tab => true,          // Tab should be rejected
            Self::Mixed { .. } => true, // Mixed whitespace should be rejected
            Self::None => true,         // Missing delimiter should be rejected
            Self::TabOnly => true,      // Tab only should be rejected
        }
    }
}

impl SpaceDelimiterFuzz {
    /// Generate the request line targeting space delimiter logic
    fn generate_request_line(&self) -> Vec<u8> {
        let mut line = Vec::new();

        // Add leading spaces (should cause rejection if > 0)
        line.extend(vec![b' '; self.space_config.leading_spaces.min(5) as usize]);

        // Add method
        line.extend_from_slice(self.method.as_str().as_bytes());

        // Add method-URI delimiter (the key test)
        line.extend_from_slice(&self.space_config.method_uri_spaces.generate_bytes());

        // Add URI
        line.extend_from_slice(self.uri.as_str().as_bytes());

        // Add URI-version delimiter (the key test)
        line.extend_from_slice(&self.space_config.uri_version_spaces.generate_bytes());

        // Add version
        line.extend_from_slice(self.version.as_str().as_bytes());

        // Add trailing spaces (should cause rejection if > 0)
        line.extend(vec![
            b' ';
            self.space_config.trailing_spaces.min(5) as usize
        ]);

        // Add CRLF termination
        line.extend_from_slice(b"\r\n");

        // Add minimal headers to complete the request
        line.extend_from_slice(b"Host: example.com\r\n\r\n");

        line
    }

    fn should_be_rejected(&self) -> bool {
        // Request should be rejected if:
        // 1. Method-URI delimiter is invalid
        // 2. URI-version delimiter is invalid
        // 3. Leading/trailing spaces are present
        self.space_config.method_uri_spaces.should_be_rejected()
            || self.space_config.uri_version_spaces.should_be_rejected()
            || self.space_config.leading_spaces > 0
            || self.space_config.trailing_spaces > 0
    }
}

fuzz_target!(|fuzz_spec: SpaceDelimiterFuzz| {
    let request_data = fuzz_spec.generate_request_line();

    // Prevent excessive input size
    if request_data.len() > MAX_INPUT_SIZE {
        return;
    }

    let expected_rejection = fuzz_spec.should_be_rejected();

    // Test the HTTP/1.1 codec
    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::from(request_data.as_slice());

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| codec.decode(&mut buf)));

    match result {
        Ok(parse_result) => {
            match (expected_rejection, parse_result) {
                (true, Ok(Some(_))) => {
                    // Codec accepted input that should have been rejected
                    let debug_str = String::from_utf8_lossy(&request_data);
                    let debug_line = debug_str.lines().next().unwrap_or(&debug_str);
                    panic!(
                        "Codec accepted request with invalid space delimiters: '{}'",
                        debug_line.escape_debug()
                    );
                }
                (false, Err(HttpError::BadRequestLine)) => {
                    // Codec rejected a valid single-space request
                    let debug_str = String::from_utf8_lossy(&request_data);
                    let debug_line = debug_str.lines().next().unwrap_or(&debug_str);
                    panic!(
                        "Codec rejected valid single-space request: '{}'",
                        debug_line.escape_debug()
                    );
                }
                (true, Err(HttpError::BadRequestLine)) => {
                    // Expected: codec correctly rejected invalid delimiters
                }
                (false, Ok(Some(_))) => {
                    // Expected: codec correctly accepted single-space delimiters
                }
                (_, Ok(None)) => {
                    // Incomplete request (needs more data) - OK for fuzzing
                }
                (_, Err(_)) => {
                    // Other error types are acceptable (bad method, version, etc.)
                }
            }
        }
        Err(_) => {
            // Codec panicked - this is a bug regardless of input
            let debug_str = String::from_utf8_lossy(&request_data);
            panic!(
                "HTTP/1.1 codec panicked on space delimiter test: '{}'",
                debug_str
                    .lines()
                    .next()
                    .unwrap_or("(non-UTF8)")
                    .escape_debug()
            );
        }
    }

    // Test partial parsing to exercise buffer management
    if request_data.len() > 10 {
        let mut partial_codec = Http1Codec::new();
        let mut partial_buf = BytesMut::from(&request_data[..request_data.len() / 2]);
        let _ = partial_codec.decode(&mut partial_buf);

        // Add remaining data
        partial_buf.extend_from_slice(&request_data[request_data.len() / 2..]);
        let _ = partial_codec.decode(&mut partial_buf);
    }
});
