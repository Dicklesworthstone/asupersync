//! Focused fuzz target for HTTP/1.1 request line parsing
//!
//! This fuzzer specifically targets the request line parsing logic in
//! src/http/h1/codec.rs, focusing on the parse_request_line_bytes function
//! and its fast/slow path handling.
//!
//! Target coverage:
//! - METHOD SP URI SP VERSION parsing (fast path)
//! - Edge cases with extra whitespace (slow path)
//! - Invalid method names and HTTP version strings
//! - URI encoding edge cases and malformed URIs
//! - Request line length limits and boundary conditions
//! - ASCII/UTF-8 validation edge cases
//! - Whitespace handling variations (spaces, tabs, etc.)

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::codec::Http1Codec;
use libfuzzer_sys::fuzz_target;
use std::hint::black_box;

/// Request line fuzz test specification
#[derive(Arbitrary, Debug)]
struct RequestLineFuzz {
    /// The HTTP method to test
    method: HttpMethodFuzz,
    /// The URI to test
    uri: UriFuzz,
    /// The HTTP version to test
    version: HttpVersionFuzz,
    /// Whitespace variations
    whitespace: WhitespaceFuzz,
    /// Additional malformation options
    malformation: MalformationFuzz,
}

/// HTTP method variations for fuzzing
#[derive(Arbitrary, Debug)]
enum HttpMethodFuzz {
    /// Standard HTTP methods
    Standard(StandardMethod),
    /// Custom method string
    Custom(String),
    /// Empty method
    Empty,
    /// Method with invalid characters
    Invalid(Vec<u8>),
    /// Extremely long method
    Long(usize),
}

#[derive(Arbitrary, Debug)]
enum StandardMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Trace,
    Connect,
    Patch,
}

impl StandardMethod {
    fn as_bytes(&self) -> &'static [u8] {
        match self {
            Self::Get => b"GET",
            Self::Post => b"POST",
            Self::Put => b"PUT",
            Self::Delete => b"DELETE",
            Self::Head => b"HEAD",
            Self::Options => b"OPTIONS",
            Self::Trace => b"TRACE",
            Self::Connect => b"CONNECT",
            Self::Patch => b"PATCH",
        }
    }
}

/// URI variations for fuzzing
#[derive(Arbitrary, Debug)]
enum UriFuzz {
    /// Simple path
    Simple(String),
    /// Path with query string
    WithQuery { path: String, query: String },
    /// Root path
    Root,
    /// Empty URI
    Empty,
    /// URI with invalid characters
    Invalid(Vec<u8>),
    /// Extremely long URI
    Long(usize),
    /// URI with percent encoding
    Encoded(String),
    /// URI with spaces and special characters
    Special(Vec<u8>),
}

/// HTTP version variations for fuzzing
#[derive(Arbitrary, Debug)]
enum HttpVersionFuzz {
    /// HTTP/1.0
    Http10,
    /// HTTP/1.1
    Http11,
    /// HTTP/2.0 (should be unsupported)
    Http20,
    /// Custom version string
    Custom(String),
    /// Empty version
    Empty,
    /// Invalid version format
    Invalid(Vec<u8>),
}

impl HttpVersionFuzz {
    fn as_bytes(&self) -> Vec<u8> {
        match self {
            Self::Http10 => b"HTTP/1.0".to_vec(),
            Self::Http11 => b"HTTP/1.1".to_vec(),
            Self::Http20 => b"HTTP/2.0".to_vec(),
            Self::Custom(s) => s.as_bytes().to_vec(),
            Self::Empty => Vec::new(),
            Self::Invalid(bytes) => bytes.clone(),
        }
    }
}

/// Whitespace handling variations
#[derive(Arbitrary, Debug)]
struct WhitespaceFuzz {
    /// Number of spaces before method
    leading_spaces: u8,
    /// Number of spaces between method and URI
    method_uri_spaces: u8,
    /// Number of spaces between URI and version
    uri_version_spaces: u8,
    /// Number of spaces after version
    trailing_spaces: u8,
    /// Use tabs instead of spaces
    use_tabs: bool,
    /// Mix spaces and tabs
    mixed_whitespace: bool,
}

/// Request line malformation options
#[derive(Arbitrary, Debug)]
struct MalformationFuzz {
    /// Missing spaces entirely
    no_spaces: bool,
    /// Missing URI (method version only)
    missing_uri: bool,
    /// Missing version (method uri only)
    missing_version: bool,
    /// Extra components beyond method uri version
    extra_components: Vec<String>,
    /// Non-ASCII characters
    non_ascii: bool,
    /// Control characters
    control_chars: bool,
    /// Null bytes
    null_bytes: bool,
}

impl RequestLineFuzz {
    /// Generate a request line based on fuzz specification
    fn generate_request_line(&self) -> Vec<u8> {
        let mut line = Vec::new();

        // Add leading spaces
        self.add_whitespace(&mut line, self.whitespace.leading_spaces);

        // Add method
        match &self.method {
            HttpMethodFuzz::Standard(method) => line.extend_from_slice(method.as_bytes()),
            HttpMethodFuzz::Custom(method) => line.extend_from_slice(method.as_bytes()),
            HttpMethodFuzz::Empty => {}, // No method
            HttpMethodFuzz::Invalid(bytes) => line.extend_from_slice(bytes),
            HttpMethodFuzz::Long(len) => {
                line.extend(std::iter::repeat(b'M').take(*len));
            }
        }

        if !self.malformation.no_spaces && !self.malformation.missing_uri {
            self.add_whitespace(&mut line, self.whitespace.method_uri_spaces.max(1));

            // Add URI
            match &self.uri {
                UriFuzz::Simple(uri) => line.extend_from_slice(uri.as_bytes()),
                UriFuzz::WithQuery { path, query } => {
                    line.extend_from_slice(path.as_bytes());
                    line.push(b'?');
                    line.extend_from_slice(query.as_bytes());
                }
                UriFuzz::Root => line.push(b'/'),
                UriFuzz::Empty => {}, // No URI
                UriFuzz::Invalid(bytes) => line.extend_from_slice(bytes),
                UriFuzz::Long(len) => {
                    line.push(b'/');
                    line.extend(std::iter::repeat(b'x').take(*len));
                }
                UriFuzz::Encoded(uri) => {
                    for byte in uri.bytes() {
                        if byte.is_ascii_alphanumeric() || b"/-_.~".contains(&byte) {
                            line.push(byte);
                        } else {
                            line.extend_from_slice(format!("%{:02X}", byte).as_bytes());
                        }
                    }
                }
                UriFuzz::Special(bytes) => line.extend_from_slice(bytes),
            }
        }

        if !self.malformation.no_spaces && !self.malformation.missing_version {
            self.add_whitespace(&mut line, self.whitespace.uri_version_spaces.max(1));

            // Add version
            line.extend_from_slice(&self.version.as_bytes());
        }

        // Add trailing spaces
        self.add_whitespace(&mut line, self.whitespace.trailing_spaces);

        // Add extra components
        for component in &self.malformation.extra_components {
            line.push(b' ');
            line.extend_from_slice(component.as_bytes());
        }

        // Apply malformations
        if self.malformation.non_ascii {
            // Insert some non-ASCII bytes
            line.push(0xFF);
            line.push(0xFE);
        }

        if self.malformation.control_chars {
            // Insert control characters
            line.push(0x01); // SOH
            line.push(0x1F); // Unit separator
        }

        if self.malformation.null_bytes {
            line.insert(line.len() / 2, 0x00);
        }

        line
    }

    fn add_whitespace(&self, line: &mut Vec<u8>, count: u8) {
        let whitespace_char = if self.whitespace.use_tabs {
            b'\t'
        } else {
            b' '
        };

        if self.whitespace.mixed_whitespace {
            for i in 0..count {
                if i % 2 == 0 {
                    line.push(b' ');
                } else {
                    line.push(b'\t');
                }
            }
        } else {
            line.extend(std::iter::repeat(whitespace_char).take(count as usize));
        }
    }
}

/// Generate a minimal corpus of known-good and edge case request lines
fn generate_corpus_entry(spec: &RequestLineFuzz) -> Vec<u8> {
    let mut request_line = spec.generate_request_line();

    // Add CRLF terminator for complete HTTP request line
    request_line.extend_from_slice(b"\r\n");

    // Add minimal headers to make it a complete HTTP request
    request_line.extend_from_slice(b"Host: example.com\r\n");
    request_line.extend_from_slice(b"\r\n");

    request_line
}

fuzz_target!(|fuzz_spec: RequestLineFuzz| {
    // Generate the request line
    let request_data = generate_corpus_entry(&fuzz_spec);

    // Ensure we don't exceed reasonable limits for fuzzing
    if request_data.len() > 1024 * 1024 {
        return;
    }

    // Create codec and test parsing
    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::from(request_data.as_slice());

    // Test the parsing - we don't care if it fails, just that it doesn't crash
    let result = black_box(codec.decode(&mut buf));

    // Also test with partial data to exercise buffering logic
    if request_data.len() > 10 {
        let mut partial_buf = BytesMut::from(&request_data[..request_data.len() / 2]);
        let _ = black_box(codec.decode(&mut partial_buf));

        // Add the rest of the data
        partial_buf.extend_from_slice(&request_data[request_data.len() / 2..]);
        let _ = black_box(codec.decode(&mut partial_buf));
    }

    // Test with extra data after complete request
    let mut extended_buf = BytesMut::from(request_data.as_slice());
    extended_buf.extend_from_slice(b"GET /extra HTTP/1.1\r\n\r\n");
    let _ = black_box(codec.decode(&mut extended_buf));

    // Exercise any remaining state
    drop(result);
    drop(codec);
});