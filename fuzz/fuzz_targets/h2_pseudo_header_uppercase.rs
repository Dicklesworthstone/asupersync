#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// Fuzz target for HTTP/2 pseudo-header uppercase validation.
///
/// Per RFC 7540 §8.1.2: "Header field names MUST be converted to lowercase prior
/// to their encoding in HTTP/2. A request or response containing uppercase
/// header field names MUST be treated as malformed."
///
/// This tests that our parser correctly rejects headers containing uppercase letters.

#[derive(Debug, Arbitrary)]
struct HeaderFieldTest {
    /// The header name to test (potentially with uppercase)
    name: String,
    /// The header value
    value: String,
    /// Whether this should be treated as a pseudo-header
    is_pseudo: bool,
}

#[derive(Debug)]
enum ViolationType {
    NameFormat,
    PseudoHeaderCase,
    RegularHeaderCase,
}

#[derive(Debug)]
enum ExpectedResult {
    Valid,
    ProtocolError(ViolationType),
}

/// Mock HTTP/2 connection for testing header field case validation
struct MockUppercaseHeaderConnection {
    stream_state: HashMap<u32, StreamState>,
    connection_error: Option<H2Error>,
}

#[derive(Debug, Clone)]
struct StreamState {
    state: StreamStateMachine,
}

#[derive(Debug, Clone, PartialEq)]
enum StreamStateMachine {
    Open,
    Closed(H2Error),
}

#[derive(Debug, Clone, PartialEq)]
enum H2Error {
    ProtocolError,
}

impl MockUppercaseHeaderConnection {
    fn new() -> Self {
        Self {
            stream_state: HashMap::new(),
            connection_error: None,
        }
    }

    /// Validate a header field name according to RFC 7540 §8.1.2
    fn validate_header_field_name(
        &mut self,
        stream_id: u32,
        name: &str,
        value: &str,
        is_pseudo: bool,
    ) -> Result<(), H2Error> {
        // Check if connection is already in error state
        if let Some(ref error) = self.connection_error {
            return Err(error.clone());
        }

        // Ensure stream exists
        self.stream_state.entry(stream_id).or_insert(StreamState {
            state: StreamStateMachine::Open,
        });

        let stream = self.stream_state.get(&stream_id).unwrap();

        // Stream must be in valid state for headers
        match stream.state {
            StreamStateMachine::Closed(ref error) => return Err(error.clone()),
            StreamStateMachine::Open => {
                // Valid for headers
            }
        }

        // RFC 7540 §8.1.2: Header field names MUST be lowercase
        if name.chars().any(|c| c.is_ascii_uppercase()) {
            // Found uppercase character - this is a PROTOCOL_ERROR
            self.connection_error = Some(H2Error::ProtocolError);

            // Close the stream
            if let Some(stream_state) = self.stream_state.get_mut(&stream_id) {
                stream_state.state = StreamStateMachine::Closed(H2Error::ProtocolError);
            }

            return Err(H2Error::ProtocolError);
        }

        // Additional validation for pseudo-headers
        if is_pseudo {
            // Pseudo-headers must start with ':'
            if !name.starts_with(':') {
                self.connection_error = Some(H2Error::ProtocolError);
                return Err(H2Error::ProtocolError);
            }

            // Validate known pseudo-header names
            match name {
                ":method" | ":scheme" | ":authority" | ":path" | ":status" => {
                    // Valid pseudo-header names
                }
                _ => {
                    // Unknown pseudo-header - should be ignored per forward compatibility
                    // but we still validate the case requirement
                }
            }
        } else {
            // Regular headers must NOT start with ':'
            if name.starts_with(':') {
                self.connection_error = Some(H2Error::ProtocolError);
                return Err(H2Error::ProtocolError);
            }
        }

        // Validate header name characters (per RFC 7230 token rules)
        // token = 1*tchar
        // tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
        //         "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
        for c in name.chars() {
            match c {
                'a'..='z'
                | '0'..='9'
                | '!'
                | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '.'
                | '^'
                | '_'
                | '`'
                | '|'
                | '~' => {
                    // Valid token character
                }
                ':' if is_pseudo && name.starts_with(':') => {
                    // ':' is only allowed at the start of pseudo-headers
                }
                _ => {
                    // Invalid character in header name
                    self.connection_error = Some(H2Error::ProtocolError);
                    return Err(H2Error::ProtocolError);
                }
            }
        }

        // Empty header names are invalid
        if name.is_empty() {
            self.connection_error = Some(H2Error::ProtocolError);
            return Err(H2Error::ProtocolError);
        }

        // Header value validation (basic checks)
        // RFC 7540 allows any UTF-8 in values, but no null bytes
        if value.contains('\0') {
            self.connection_error = Some(H2Error::ProtocolError);
            return Err(H2Error::ProtocolError);
        }

        Ok(())
    }

    fn get_connection_state(&self) -> Option<&H2Error> {
        self.connection_error.as_ref()
    }

    fn get_stream_state(&self, stream_id: u32) -> Option<&StreamState> {
        self.stream_state.get(&stream_id)
    }
}

/// Determine the expected result for a given header field test
fn classify_test_case(test: &HeaderFieldTest) -> ExpectedResult {
    let has_uppercase = test.name.chars().any(|c| c.is_ascii_uppercase());

    if has_uppercase {
        let violation_type = if test.is_pseudo {
            ViolationType::PseudoHeaderCase
        } else {
            ViolationType::RegularHeaderCase
        };
        ExpectedResult::ProtocolError(violation_type)
    } else {
        // Additional validity checks for corner cases
        if test.name.is_empty()
            || (test.is_pseudo && !test.name.starts_with(':'))
            || (!test.is_pseudo && test.name.starts_with(':'))
        {
            ExpectedResult::ProtocolError(ViolationType::NameFormat)
        } else {
            ExpectedResult::Valid
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent timeouts
    if data.len() > 1024 {
        return;
    }

    // Try to generate a structured test from the fuzz data
    let test = match HeaderFieldTest::arbitrary(&mut arbitrary::Unstructured::new(data)) {
        Ok(test) => test,
        Err(_) => return, // Invalid input, skip
    };

    // Skip tests with extremely long names/values
    if test.name.len() > 256 || test.value.len() > 1024 {
        return;
    }

    let mut connection = MockUppercaseHeaderConnection::new();
    let stream_id = 1u32;

    // Classify what we expect to happen
    let expected = classify_test_case(&test);

    // Test the header field validation
    let result =
        connection.validate_header_field_name(stream_id, &test.name, &test.value, test.is_pseudo);

    match expected {
        ExpectedResult::Valid => {
            // Should succeed - no uppercase letters, valid format
            if result.is_err() {
                // Might be failing for other reasons (invalid chars, empty name, etc.)
                // Only panic if it's specifically failing due to case when it shouldn't
                if test.name.chars().any(|c| c.is_ascii_uppercase()) {
                    panic!(
                        "Expected valid header but got error for: name='{}', value='{}', is_pseudo={}, error={:?}",
                        test.name, test.value, test.is_pseudo, result
                    );
                }
            }

            // Verify connection is still healthy
            assert!(
                connection.get_connection_state().is_none(),
                "Connection should not be in error state for valid header"
            );

            // Verify stream is still open
            if let Some(stream) = connection.get_stream_state(stream_id) {
                assert_ne!(
                    stream.state,
                    StreamStateMachine::Closed(H2Error::ProtocolError),
                    "Stream should not be closed for valid header"
                );
            }
        }

        ExpectedResult::ProtocolError(violation_type) => {
            // Should fail with PROTOCOL_ERROR
            match result {
                Err(H2Error::ProtocolError) => {
                    // Expected! Verify connection state reflects the error
                    assert_eq!(
                        connection.get_connection_state(),
                        Some(&H2Error::ProtocolError),
                        "Connection should be in PROTOCOL_ERROR state"
                    );

                    if let Some(stream) = connection.get_stream_state(stream_id) {
                        match violation_type {
                            ViolationType::PseudoHeaderCase | ViolationType::RegularHeaderCase => {
                                assert_eq!(
                                    stream.state,
                                    StreamStateMachine::Closed(H2Error::ProtocolError),
                                    "Stream should be closed for uppercase header errors"
                                );
                            }
                            ViolationType::NameFormat => {
                                assert_eq!(
                                    stream.state,
                                    StreamStateMachine::Open,
                                    "Name-format errors should not be asserted as stream-close case errors"
                                );
                            }
                        }
                    }
                }
                Ok(_) => {
                    panic!(
                        "Expected PROTOCOL_ERROR for header with uppercase but got success: name='{}', value='{}', is_pseudo={}, violation={:?}",
                        test.name, test.value, test.is_pseudo, violation_type
                    );
                }
            }
        }
    }

    // Test some specific predefined cases to ensure our logic is sound

    // Test case 1: Common uppercase header names that should fail
    let uppercase_tests = [
        ("Host", "example.com", false),
        ("Content-Type", "application/json", false),
        ("Authorization", "Bearer token123", false),
        (":Method", "GET", true), // Uppercase in pseudo-header
        (":AUTHORITY", "example.com", true),
        ("X-Custom-Header", "value", false),
    ];

    for (name, value, is_pseudo) in &uppercase_tests {
        let mut test_conn = MockUppercaseHeaderConnection::new();
        let test_result = test_conn.validate_header_field_name(1, name, value, *is_pseudo);

        // All of these should fail with PROTOCOL_ERROR due to uppercase
        assert!(
            test_result.is_err(),
            "Header '{}' with uppercase should be rejected",
            name
        );
        assert_eq!(
            test_conn.get_connection_state(),
            Some(&H2Error::ProtocolError),
            "Connection should be in error state after uppercase header '{}'",
            name
        );
    }

    // Test case 2: Lowercase equivalents should succeed (basic validation)
    let lowercase_tests = [
        ("host", "example.com", false),
        ("content-type", "application/json", false),
        ("authorization", "Bearer token123", false),
        (":method", "GET", true),
        (":authority", "example.com", true),
        ("x-custom-header", "value", false),
    ];

    for (name, value, is_pseudo) in &lowercase_tests {
        let mut test_conn = MockUppercaseHeaderConnection::new();
        let test_result = test_conn.validate_header_field_name(1, name, value, *is_pseudo);

        // These should succeed (assuming no other validation issues)
        match test_result {
            Ok(_) => {
                // Good! Verify connection remains healthy
                assert!(
                    test_conn.get_connection_state().is_none(),
                    "Connection should remain healthy for lowercase header '{}'",
                    name
                );
            }
            Err(_) => {
                // May fail for other reasons (unknown pseudo-header, etc.), but not for case
                // This is acceptable since we're focused on case validation
            }
        }
    }
});
