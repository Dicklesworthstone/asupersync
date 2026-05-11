#![no_main]
#![allow(dead_code)]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/2 unknown pseudo-header test input for RFC 7540 §8.1.2 compliance
#[derive(Arbitrary, Debug)]
struct H2UnknownPseudoHeaderInput {
    /// Type of message being tested
    message_type: MessageType,
    /// Pseudo-header testing strategy
    pseudo_header_strategy: PseudoHeaderStrategy,
    /// Additional headers to include
    regular_headers: Vec<RegularHeader>,
    /// Test context
    test_context: TestContext,
}

#[derive(Arbitrary, Debug)]
enum MessageType {
    /// HTTP request
    Request,
    /// HTTP response
    Response,
    /// Trailers (pseudo-headers forbidden)
    Trailers,
}

#[derive(Arbitrary, Debug)]
enum PseudoHeaderStrategy {
    /// Single unknown pseudo-header
    SingleUnknown(UnknownPseudoHeader),
    /// Multiple unknown pseudo-headers
    MultipleUnknown(Vec<UnknownPseudoHeader>),
    /// Mix of known and unknown pseudo-headers
    MixedKnownUnknown {
        known: Vec<KnownPseudoHeader>,
        unknown: Vec<UnknownPseudoHeader>,
    },
    /// Wrong context pseudo-headers (request headers in response, etc.)
    WrongContext(WrongContextHeaders),
    /// Malformed pseudo-headers
    Malformed(Vec<MalformedPseudoHeader>),
    /// Duplicate pseudo-headers (some unknown)
    Duplicates {
        first: UnknownPseudoHeader,
        second: UnknownPseudoHeader,
    },
}

#[derive(Arbitrary, Debug)]
struct UnknownPseudoHeader {
    /// Name of the unknown pseudo-header (without leading :)
    name: String,
    /// Value of the pseudo-header
    value: String,
    /// Position relative to known pseudo-headers
    position: HeaderPosition,
}

#[derive(Arbitrary, Debug)]
enum HeaderPosition {
    /// Before all known pseudo-headers
    Before,
    /// Between known pseudo-headers
    Between,
    /// After all known pseudo-headers but before regular headers
    AfterPseudo,
    /// Mixed with regular headers (invalid)
    Mixed,
}

#[derive(Arbitrary, Debug)]
enum KnownPseudoHeader {
    /// :method for requests
    Method(String),
    /// :scheme for requests
    Scheme(String),
    /// :authority for requests
    Authority(String),
    /// :path for requests
    Path(String),
    /// :status for responses
    Status(u16),
}

#[derive(Arbitrary, Debug)]
enum WrongContextHeaders {
    /// Request pseudo-headers in response
    RequestInResponse {
        method: Option<String>,
        scheme: Option<String>,
        authority: Option<String>,
        path: Option<String>,
    },
    /// Response pseudo-headers in request
    ResponseInRequest { status: u16 },
    /// Pseudo-headers in trailers
    PseudoInTrailers(Vec<UnknownPseudoHeader>),
}

#[derive(Arbitrary, Debug)]
struct MalformedPseudoHeader {
    /// The malformed header name
    name: String,
    /// The header value
    value: String,
    /// Type of malformation
    malformation_type: MalformationType,
}

#[derive(Arbitrary, Debug)]
enum MalformationType {
    /// Just ":" with no name
    EmptyName,
    /// ":" followed by numbers
    NumericName,
    /// ":" followed by special characters
    SpecialCharName,
    /// ":" followed by uppercase letters
    UppercaseName,
    /// Multiple colons
    MultipleColons,
    /// Colon in the middle
    ColonInMiddle,
}

#[derive(Arbitrary, Debug)]
struct RegularHeader {
    name: String,
    value: String,
}

#[derive(Arbitrary, Debug)]
struct TestContext {
    /// HTTP/2 stream ID
    stream_id: u32,
    /// Whether this is a HEADERS or CONTINUATION frame
    frame_type: FrameType,
    /// Whether END_HEADERS flag is set
    end_headers: bool,
    /// HPACK compression context
    hpack_context: HpackContext,
}

#[derive(Arbitrary, Debug)]
enum FrameType {
    Headers,
    Continuation,
    PushPromise,
}

#[derive(Arbitrary, Debug)]
struct HpackContext {
    /// Dynamic table size
    table_size: u16,
    /// Use literal indexing
    use_literal: bool,
}

/// Mock HTTP/2 pseudo-header parser for testing RFC 7540 §8.1.2 compliance
struct MockH2PseudoHeaderParser;

#[derive(Debug, PartialEq)]
enum PseudoHeaderValidationError {
    /// Unknown pseudo-header field (PROTOCOL_ERROR)
    UnknownPseudoHeader { name: String },
    /// Pseudo-header in wrong context (request in response, etc.)
    WrongContext { header: String, context: String },
    /// Pseudo-header in trailers (forbidden)
    PseudoInTrailers { name: String },
    /// Malformed pseudo-header name
    MalformedPseudoHeader { name: String },
    /// Duplicate pseudo-header
    DuplicatePseudoHeader { name: String },
    /// Pseudo-header after regular header
    PseudoAfterRegular { name: String },
    /// Required pseudo-header missing
    RequiredPseudoMissing { required: String },
    /// Invalid pseudo-header value
    InvalidPseudoValue { name: String, value: String },
}

impl MockH2PseudoHeaderParser {
    fn validate_headers(
        input: &H2UnknownPseudoHeaderInput,
    ) -> Result<(), PseudoHeaderValidationError> {
        // Check if pseudo-headers are allowed in this context
        if matches!(input.message_type, MessageType::Trailers) {
            // RFC 7540 §8.1.2: Pseudo-headers MUST NOT appear in trailers
            return Self::check_pseudo_in_trailers(input);
        }

        // Generate the complete header list
        let headers = Self::generate_header_list(input);

        // Validate header ordering (pseudo-headers must come first)
        Self::validate_header_ordering(&headers)?;

        // Validate each pseudo-header
        for (name, value) in &headers {
            if name.starts_with(':') {
                Self::validate_pseudo_header(name, value, &input.message_type)?;
            }
        }

        Ok(())
    }

    fn check_pseudo_in_trailers(
        input: &H2UnknownPseudoHeaderInput,
    ) -> Result<(), PseudoHeaderValidationError> {
        match &input.pseudo_header_strategy {
            PseudoHeaderStrategy::SingleUnknown(unknown) => {
                return Err(PseudoHeaderValidationError::PseudoInTrailers {
                    name: format!(":{}", unknown.name),
                });
            }
            PseudoHeaderStrategy::MultipleUnknown(unknowns) => {
                if !unknowns.is_empty() {
                    return Err(PseudoHeaderValidationError::PseudoInTrailers {
                        name: format!(":{}", unknowns[0].name),
                    });
                }
            }
            PseudoHeaderStrategy::WrongContext(WrongContextHeaders::PseudoInTrailers(headers)) => {
                if !headers.is_empty() {
                    return Err(PseudoHeaderValidationError::PseudoInTrailers {
                        name: format!(":{}", headers[0].name),
                    });
                }
            }
            _ => {
                // Check if any pseudo-headers were generated
                let headers = Self::generate_header_list(input);
                for (name, _) in headers {
                    if name.starts_with(':') {
                        return Err(PseudoHeaderValidationError::PseudoInTrailers { name });
                    }
                }
            }
        }
        Ok(())
    }

    fn generate_header_list(input: &H2UnknownPseudoHeaderInput) -> Vec<(String, String)> {
        let mut headers = Vec::new();

        match &input.pseudo_header_strategy {
            PseudoHeaderStrategy::SingleUnknown(unknown) => {
                let header_name = Self::format_pseudo_header_name(&unknown.name);
                headers.push((header_name, unknown.value.clone()));
            }
            PseudoHeaderStrategy::MultipleUnknown(unknowns) => {
                for unknown in unknowns {
                    let header_name = Self::format_pseudo_header_name(&unknown.name);
                    headers.push((header_name, unknown.value.clone()));
                }
            }
            PseudoHeaderStrategy::MixedKnownUnknown { known, unknown } => {
                // Add known pseudo-headers first
                for known_header in known {
                    let (name, value) =
                        Self::format_known_pseudo_header(known_header, &input.message_type);
                    headers.push((name, value));
                }
                // Add unknown pseudo-headers
                for unknown_header in unknown {
                    let header_name = Self::format_pseudo_header_name(&unknown_header.name);
                    headers.push((header_name, unknown_header.value.clone()));
                }
            }
            PseudoHeaderStrategy::WrongContext(wrong_context) => match wrong_context {
                WrongContextHeaders::RequestInResponse {
                    method,
                    scheme,
                    authority,
                    path,
                } => {
                    if let Some(m) = method {
                        headers.push((":method".to_string(), m.clone()));
                    }
                    if let Some(s) = scheme {
                        headers.push((":scheme".to_string(), s.clone()));
                    }
                    if let Some(a) = authority {
                        headers.push((":authority".to_string(), a.clone()));
                    }
                    if let Some(p) = path {
                        headers.push((":path".to_string(), p.clone()));
                    }
                }
                WrongContextHeaders::ResponseInRequest { status } => {
                    headers.push((":status".to_string(), status.to_string()));
                }
                WrongContextHeaders::PseudoInTrailers(trailer_headers) => {
                    for unknown in trailer_headers {
                        let header_name = Self::format_pseudo_header_name(&unknown.name);
                        headers.push((header_name, unknown.value.clone()));
                    }
                }
            },
            PseudoHeaderStrategy::Malformed(malformed) => {
                for malformed_header in malformed {
                    let name = Self::format_malformed_header(malformed_header);
                    headers.push((name, malformed_header.value.clone()));
                }
            }
            PseudoHeaderStrategy::Duplicates { first, second } => {
                let first_name = Self::format_pseudo_header_name(&first.name);
                let second_name = Self::format_pseudo_header_name(&second.name);
                headers.push((first_name.clone(), first.value.clone()));
                headers.push((second_name, second.value.clone()));
            }
        }

        // Add regular headers
        for regular in &input.regular_headers {
            headers.push((regular.name.clone(), regular.value.clone()));
        }

        headers
    }

    fn format_pseudo_header_name(name: &str) -> String {
        if name.is_empty() {
            ":".to_string()
        } else {
            format!(":{}", name)
        }
    }

    fn format_known_pseudo_header(
        known: &KnownPseudoHeader,
        _message_type: &MessageType,
    ) -> (String, String) {
        match known {
            KnownPseudoHeader::Method(method) => (":method".to_string(), method.clone()),
            KnownPseudoHeader::Scheme(scheme) => (":scheme".to_string(), scheme.clone()),
            KnownPseudoHeader::Authority(authority) => {
                (":authority".to_string(), authority.clone())
            }
            KnownPseudoHeader::Path(path) => (":path".to_string(), path.clone()),
            KnownPseudoHeader::Status(status) => (":status".to_string(), status.to_string()),
        }
    }

    fn format_malformed_header(malformed: &MalformedPseudoHeader) -> String {
        match malformed.malformation_type {
            MalformationType::EmptyName => ":".to_string(),
            MalformationType::NumericName => format!(":123{}", malformed.name),
            MalformationType::SpecialCharName => format!(":#{}", malformed.name),
            MalformationType::UppercaseName => format!(":UPPER{}", malformed.name),
            MalformationType::MultipleColons => format!(":::{}", malformed.name),
            MalformationType::ColonInMiddle => format!("{}:{}", malformed.name, malformed.name),
        }
    }

    fn validate_header_ordering(
        headers: &[(String, String)],
    ) -> Result<(), PseudoHeaderValidationError> {
        let mut seen_regular = false;

        for (name, _) in headers {
            if name.starts_with(':') {
                if seen_regular {
                    return Err(PseudoHeaderValidationError::PseudoAfterRegular {
                        name: name.clone(),
                    });
                }
            } else {
                seen_regular = true;
            }
        }

        Ok(())
    }

    fn validate_pseudo_header(
        name: &str,
        value: &str,
        message_type: &MessageType,
    ) -> Result<(), PseudoHeaderValidationError> {
        // Check if it's a known pseudo-header
        let known_request_pseudo = matches!(name, ":method" | ":scheme" | ":authority" | ":path");
        let known_response_pseudo = matches!(name, ":status");

        if !known_request_pseudo && !known_response_pseudo {
            // Unknown pseudo-header - RFC 7540 §8.1.2 violation
            return Err(PseudoHeaderValidationError::UnknownPseudoHeader {
                name: name.to_string(),
            });
        }

        // Check context appropriateness
        match message_type {
            MessageType::Request => {
                if known_response_pseudo {
                    return Err(PseudoHeaderValidationError::WrongContext {
                        header: name.to_string(),
                        context: "request".to_string(),
                    });
                }
            }
            MessageType::Response => {
                if known_request_pseudo {
                    return Err(PseudoHeaderValidationError::WrongContext {
                        header: name.to_string(),
                        context: "response".to_string(),
                    });
                }
            }
            MessageType::Trailers => {
                // All pseudo-headers are forbidden in trailers
                return Err(PseudoHeaderValidationError::PseudoInTrailers {
                    name: name.to_string(),
                });
            }
        }

        // Validate specific pseudo-header values
        Self::validate_pseudo_header_value(name, value)?;

        Ok(())
    }

    fn validate_pseudo_header_value(
        name: &str,
        value: &str,
    ) -> Result<(), PseudoHeaderValidationError> {
        match name {
            ":method" => {
                if value.is_empty() {
                    return Err(PseudoHeaderValidationError::InvalidPseudoValue {
                        name: name.to_string(),
                        value: value.to_string(),
                    });
                }
                // Basic method validation
                if !value
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_alphanumeric())
                {
                    return Err(PseudoHeaderValidationError::InvalidPseudoValue {
                        name: name.to_string(),
                        value: value.to_string(),
                    });
                }
            }
            ":status" => {
                // Status must be a 3-digit number
                if value.len() != 3 || !value.chars().all(|c| c.is_ascii_digit()) {
                    return Err(PseudoHeaderValidationError::InvalidPseudoValue {
                        name: name.to_string(),
                        value: value.to_string(),
                    });
                }
                let status_code: u16 =
                    value
                        .parse()
                        .map_err(|_| PseudoHeaderValidationError::InvalidPseudoValue {
                            name: name.to_string(),
                            value: value.to_string(),
                        })?;
                if !(100..=599).contains(&status_code) {
                    return Err(PseudoHeaderValidationError::InvalidPseudoValue {
                        name: name.to_string(),
                        value: value.to_string(),
                    });
                }
            }
            ":scheme" | ":path" if value.is_empty() => {
                return Err(PseudoHeaderValidationError::InvalidPseudoValue {
                    name: name.to_string(),
                    value: value.to_string(),
                });
            }
            _ => {
                // Other pseudo-headers or already validated above
            }
        }

        Ok(())
    }
}

fuzz_target!(|input: H2UnknownPseudoHeaderInput| {
    // Skip inputs that would cause excessive processing
    if input.regular_headers.len() > 50 {
        return;
    }

    let result = MockH2PseudoHeaderParser::validate_headers(&input);

    // Apply test assertions based on the pseudo-header strategy
    match &input.pseudo_header_strategy {
        PseudoHeaderStrategy::SingleUnknown(unknown) => {
            // Unknown pseudo-headers should always be rejected per RFC 7540 §8.1.2
            match &result {
                Err(PseudoHeaderValidationError::UnknownPseudoHeader { .. }) => {
                    // Expected: unknown pseudo-header correctly rejected
                }
                Err(PseudoHeaderValidationError::PseudoInTrailers { .. }) => {
                    // Expected: pseudo-header in trailers rejected
                }
                Err(PseudoHeaderValidationError::PseudoAfterRegular { .. }) => {
                    // Expected: pseudo-header ordering violation
                }
                Ok(()) => {
                    panic!(
                        "Unknown pseudo-header should be rejected: :{}",
                        unknown.name
                    );
                }
                Err(_) => {
                    // Other errors may occur due to additional validation
                }
            }
        }
        PseudoHeaderStrategy::MultipleUnknown(_) => {
            // Unknown pseudo-headers should always be rejected per RFC 7540 §8.1.2
            match &result {
                Err(PseudoHeaderValidationError::UnknownPseudoHeader { .. }) => {
                    // Expected: unknown pseudo-header correctly rejected
                }
                Err(PseudoHeaderValidationError::PseudoInTrailers { .. }) => {
                    // Expected: pseudo-header in trailers rejected
                }
                Err(PseudoHeaderValidationError::PseudoAfterRegular { .. }) => {
                    // Expected: pseudo-header ordering violation
                }
                Ok(()) => {
                    panic!("Unknown pseudo-header should be rejected");
                }
                Err(_) => {
                    // Other errors may occur due to additional validation
                }
            }
        }
        PseudoHeaderStrategy::WrongContext(wrong_context) => {
            // Wrong context should be rejected
            match wrong_context {
                WrongContextHeaders::RequestInResponse { .. } => {
                    assert!(matches!(&result,
                        Err(PseudoHeaderValidationError::WrongContext { context, .. })
                        if context == "response"
                    ));
                }
                WrongContextHeaders::ResponseInRequest { .. } => {
                    assert!(matches!(&result,
                        Err(PseudoHeaderValidationError::WrongContext { context, .. })
                        if context == "request"
                    ));
                }
                WrongContextHeaders::PseudoInTrailers(_) => {
                    assert!(matches!(
                        &result,
                        Err(PseudoHeaderValidationError::PseudoInTrailers { .. })
                    ));
                }
            }
        }
        PseudoHeaderStrategy::Malformed(_) => {
            // Malformed pseudo-headers should be rejected
            match &result {
                Err(PseudoHeaderValidationError::UnknownPseudoHeader { .. }) => {
                    // Expected: malformed headers treated as unknown
                }
                Err(PseudoHeaderValidationError::MalformedPseudoHeader { .. }) => {
                    // Expected: malformation detected
                }
                Ok(()) => {
                    panic!("Malformed pseudo-header should be rejected");
                }
                Err(_) => {
                    // Other errors may occur
                }
            }
        }
        PseudoHeaderStrategy::MixedKnownUnknown { unknown, .. } => {
            // Should fail due to unknown pseudo-headers
            if !unknown.is_empty() {
                assert!(matches!(
                    &result,
                    Err(PseudoHeaderValidationError::UnknownPseudoHeader { .. })
                ));
            }
        }
        PseudoHeaderStrategy::Duplicates { .. } => {
            // May be rejected for unknown pseudo-header or duplication
            match &result {
                Err(PseudoHeaderValidationError::UnknownPseudoHeader { .. }) => {
                    // Expected: unknown pseudo-header
                }
                Err(PseudoHeaderValidationError::DuplicatePseudoHeader { .. }) => {
                    // Expected: duplicate detection
                }
                Ok(()) => {
                    panic!("Duplicate pseudo-header should be rejected");
                }
                Err(_) => {
                    // Other errors may occur
                }
            }
        }
    }

    // Test invariants that should always hold
    test_pseudo_header_invariants(&input, &result);
});

fn test_pseudo_header_invariants(
    input: &H2UnknownPseudoHeaderInput,
    result: &Result<(), PseudoHeaderValidationError>,
) {
    // Invariant: Pseudo-headers in trailers must always be rejected
    if matches!(input.message_type, MessageType::Trailers) {
        let headers = MockH2PseudoHeaderParser::generate_header_list(input);
        let has_pseudo = headers.iter().any(|(name, _)| name.starts_with(':'));

        if has_pseudo {
            assert!(matches!(
                result,
                Err(PseudoHeaderValidationError::PseudoInTrailers { .. })
            ));
        }
    }

    // Invariant: Unknown pseudo-headers (not in RFC 7540) must be rejected
    let headers = MockH2PseudoHeaderParser::generate_header_list(input);
    for (name, _) in headers {
        if name.starts_with(':') {
            let is_known = matches!(
                name.as_str(),
                ":method" | ":scheme" | ":authority" | ":path" | ":status"
            );

            if !is_known && result.is_ok() {
                panic!("Unknown pseudo-header {} should be rejected", name);
            }
        }
    }

    // Invariant: Request pseudo-headers in response context should be rejected
    if matches!(input.message_type, MessageType::Response) {
        let headers = MockH2PseudoHeaderParser::generate_header_list(input);
        let has_request_pseudo = headers.iter().any(|(name, _)| {
            matches!(
                name.as_str(),
                ":method" | ":scheme" | ":authority" | ":path"
            )
        });

        if has_request_pseudo && result.is_ok() {
            panic!("Request pseudo-headers should not be allowed in response");
        }
    }

    // Invariant: Response pseudo-headers in request context should be rejected
    if matches!(input.message_type, MessageType::Request) {
        let headers = MockH2PseudoHeaderParser::generate_header_list(input);
        let has_response_pseudo = headers.iter().any(|(name, _)| name == ":status");

        if has_response_pseudo && result.is_ok() {
            panic!("Response pseudo-headers should not be allowed in request");
        }
    }

    // Invariant: Pseudo-headers after regular headers should be rejected
    let headers = MockH2PseudoHeaderParser::generate_header_list(input);
    let mut seen_regular = false;
    for (name, _) in headers {
        if name.starts_with(':') && seen_regular {
            assert!(matches!(
                result,
                Err(PseudoHeaderValidationError::PseudoAfterRegular { .. })
            ));
            break;
        }
        if !name.starts_with(':') {
            seen_regular = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unknown_pseudo_header_rejected() {
        let input = H2UnknownPseudoHeaderInput {
            message_type: MessageType::Request,
            pseudo_header_strategy: PseudoHeaderStrategy::SingleUnknown(UnknownPseudoHeader {
                name: "custom".to_string(),
                value: "test".to_string(),
                position: HeaderPosition::Before,
            }),
            regular_headers: vec![],
            test_context: TestContext {
                stream_id: 1,
                frame_type: FrameType::Headers,
                end_headers: true,
                hpack_context: HpackContext {
                    table_size: 4096,
                    use_literal: false,
                },
            },
        };

        let result = MockH2PseudoHeaderParser::validate_headers(&input);
        assert!(matches!(
            result,
            Err(PseudoHeaderValidationError::UnknownPseudoHeader { .. })
        ));
    }

    #[test]
    fn test_request_pseudo_in_response_rejected() {
        let input = H2UnknownPseudoHeaderInput {
            message_type: MessageType::Response,
            pseudo_header_strategy: PseudoHeaderStrategy::WrongContext(
                WrongContextHeaders::RequestInResponse {
                    method: Some("GET".to_string()),
                    scheme: None,
                    authority: None,
                    path: None,
                },
            ),
            regular_headers: vec![],
            test_context: TestContext {
                stream_id: 1,
                frame_type: FrameType::Headers,
                end_headers: true,
                hpack_context: HpackContext {
                    table_size: 4096,
                    use_literal: false,
                },
            },
        };

        let result = MockH2PseudoHeaderParser::validate_headers(&input);
        assert!(matches!(
            result,
            Err(PseudoHeaderValidationError::WrongContext { .. })
        ));
    }

    #[test]
    fn test_response_pseudo_in_request_rejected() {
        let input = H2UnknownPseudoHeaderInput {
            message_type: MessageType::Request,
            pseudo_header_strategy: PseudoHeaderStrategy::WrongContext(
                WrongContextHeaders::ResponseInRequest { status: 200 },
            ),
            regular_headers: vec![],
            test_context: TestContext {
                stream_id: 1,
                frame_type: FrameType::Headers,
                end_headers: true,
                hpack_context: HpackContext {
                    table_size: 4096,
                    use_literal: false,
                },
            },
        };

        let result = MockH2PseudoHeaderParser::validate_headers(&input);
        assert!(matches!(
            result,
            Err(PseudoHeaderValidationError::WrongContext { .. })
        ));
    }

    #[test]
    fn test_pseudo_in_trailers_rejected() {
        let input = H2UnknownPseudoHeaderInput {
            message_type: MessageType::Trailers,
            pseudo_header_strategy: PseudoHeaderStrategy::SingleUnknown(UnknownPseudoHeader {
                name: "custom".to_string(),
                value: "test".to_string(),
                position: HeaderPosition::Before,
            }),
            regular_headers: vec![],
            test_context: TestContext {
                stream_id: 1,
                frame_type: FrameType::Headers,
                end_headers: true,
                hpack_context: HpackContext {
                    table_size: 4096,
                    use_literal: false,
                },
            },
        };

        let result = MockH2PseudoHeaderParser::validate_headers(&input);
        assert!(matches!(
            result,
            Err(PseudoHeaderValidationError::PseudoInTrailers { .. })
        ));
    }

    #[test]
    fn test_malformed_pseudo_headers() {
        let malformed_headers = vec![
            MalformedPseudoHeader {
                name: "".to_string(),
                value: "test".to_string(),
                malformation_type: MalformationType::EmptyName,
            },
            MalformedPseudoHeader {
                name: "test".to_string(),
                value: "value".to_string(),
                malformation_type: MalformationType::UppercaseName,
            },
        ];

        let input = H2UnknownPseudoHeaderInput {
            message_type: MessageType::Request,
            pseudo_header_strategy: PseudoHeaderStrategy::Malformed(malformed_headers),
            regular_headers: vec![],
            test_context: TestContext {
                stream_id: 1,
                frame_type: FrameType::Headers,
                end_headers: true,
                hpack_context: HpackContext {
                    table_size: 4096,
                    use_literal: false,
                },
            },
        };

        let result = MockH2PseudoHeaderParser::validate_headers(&input);
        assert!(result.is_err());
    }

    #[test]
    fn test_pseudo_after_regular_rejected() {
        let input = H2UnknownPseudoHeaderInput {
            message_type: MessageType::Request,
            pseudo_header_strategy: PseudoHeaderStrategy::SingleUnknown(UnknownPseudoHeader {
                name: "custom".to_string(),
                value: "test".to_string(),
                position: HeaderPosition::Mixed,
            }),
            regular_headers: vec![RegularHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            }],
            test_context: TestContext {
                stream_id: 1,
                frame_type: FrameType::Headers,
                end_headers: true,
                hpack_context: HpackContext {
                    table_size: 4096,
                    use_literal: false,
                },
            },
        };

        let result = MockH2PseudoHeaderParser::validate_headers(&input);
        // Should fail due to either ordering violation or unknown pseudo-header
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_unknown_pseudo_headers() {
        let unknown_headers = vec![
            UnknownPseudoHeader {
                name: "custom1".to_string(),
                value: "value1".to_string(),
                position: HeaderPosition::Before,
            },
            UnknownPseudoHeader {
                name: "custom2".to_string(),
                value: "value2".to_string(),
                position: HeaderPosition::Before,
            },
        ];

        let input = H2UnknownPseudoHeaderInput {
            message_type: MessageType::Request,
            pseudo_header_strategy: PseudoHeaderStrategy::MultipleUnknown(unknown_headers),
            regular_headers: vec![],
            test_context: TestContext {
                stream_id: 1,
                frame_type: FrameType::Headers,
                end_headers: true,
                hpack_context: HpackContext {
                    table_size: 4096,
                    use_literal: false,
                },
            },
        };

        let result = MockH2PseudoHeaderParser::validate_headers(&input);
        assert!(matches!(
            result,
            Err(PseudoHeaderValidationError::UnknownPseudoHeader { .. })
        ));
    }

    #[test]
    fn test_valid_known_pseudo_headers() {
        let known_headers = vec![
            KnownPseudoHeader::Method("GET".to_string()),
            KnownPseudoHeader::Scheme("https".to_string()),
            KnownPseudoHeader::Authority("example.com".to_string()),
            KnownPseudoHeader::Path("/".to_string()),
        ];

        let input = H2UnknownPseudoHeaderInput {
            message_type: MessageType::Request,
            pseudo_header_strategy: PseudoHeaderStrategy::MixedKnownUnknown {
                known: known_headers,
                unknown: vec![],
            },
            regular_headers: vec![],
            test_context: TestContext {
                stream_id: 1,
                frame_type: FrameType::Headers,
                end_headers: true,
                hpack_context: HpackContext {
                    table_size: 4096,
                    use_literal: false,
                },
            },
        };

        let result = MockH2PseudoHeaderParser::validate_headers(&input);
        assert!(
            result.is_ok(),
            "Valid known pseudo-headers should be accepted"
        );
    }
}
