#![no_main]
#![allow(dead_code)]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/2 :method pseudo-header length test input for bounds validation
#[derive(Arbitrary, Debug)]
struct H2MethodLengthInput {
    /// Method generation strategy
    method_strategy: MethodStrategy,
    /// Length category for testing
    length_category: LengthCategory,
    /// Additional method properties
    method_properties: MethodProperties,
    /// Context for the method
    request_context: RequestContext,
}

#[derive(Arbitrary, Debug)]
enum MethodStrategy {
    /// Standard HTTP methods
    Standard(StandardMethod),
    /// Extension method with custom name
    Extension { name: String },
    /// Generated method of specific length
    Generated { target_length: usize },
    /// Padded standard method
    Padded {
        base: StandardMethod,
        padding: String,
    },
    /// Repeated character method
    Repeated { character: char, count: usize },
    /// Mixed case method
    MixedCase { base_method: String },
}

#[derive(Arbitrary, Debug)]
enum StandardMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
    Trace,
    Connect,
}

#[derive(Arbitrary, Debug)]
enum LengthCategory {
    /// Very short methods (1-3 chars)
    VeryShort,
    /// Standard methods (4-7 chars)
    Standard,
    /// Extension methods (8-16 chars)
    Extension,
    /// Long extension methods (17-64 chars)
    LongExtension,
    /// Very long methods (65-256 chars)
    VeryLong,
    /// Extremely long methods (257+ chars)
    ExtremelyLong,
    /// Boundary testing around specific limits
    Boundary(BoundaryTest),
}

#[derive(Arbitrary, Debug)]
enum BoundaryTest {
    /// Around 64 character limit
    Around64 { offset: i8 },
    /// Around 128 character limit
    Around128 { offset: i8 },
    /// Around 256 character limit
    Around256 { offset: i8 },
    /// Around 512 character limit
    Around512 { offset: i8 },
    /// Around 1024 character limit
    Around1024 { offset: i8 },
}

#[derive(Arbitrary, Debug)]
struct MethodProperties {
    /// Include special characters
    special_chars: bool,
    /// Include unicode characters
    unicode: bool,
    /// Include control characters
    control_chars: bool,
    /// Use only uppercase
    uppercase: bool,
    /// Use only lowercase
    lowercase: bool,
}

#[derive(Arbitrary, Debug)]
struct RequestContext {
    /// Other pseudo-headers
    authority: String,
    path: String,
    scheme: String,
    /// Additional headers
    user_agent: String,
    content_type: Option<String>,
}

/// Mock HTTP/2 method parser for testing length bounds
struct MockH2MethodParser {
    config: ParserConfig,
}

#[derive(Debug)]
struct ParserConfig {
    /// Maximum allowed method length
    max_method_length: usize,
    /// Whether to allow extension methods
    allow_extensions: bool,
    /// Whether to enforce uppercase methods
    enforce_uppercase: bool,
}

#[derive(Debug, PartialEq)]
enum MethodValidationError {
    /// Method too long
    MethodTooLong { length: usize, max: usize },
    /// Method contains invalid characters
    InvalidCharacters,
    /// Method is empty
    Empty,
    /// Method contains control characters
    ControlCharacters,
    /// Method contains non-ASCII characters
    NonAscii,
    /// Method case is invalid (if enforced)
    InvalidCase,
    /// Unknown method (if extensions not allowed)
    UnknownMethod,
}

impl MockH2MethodParser {
    fn new(config: ParserConfig) -> Self {
        Self { config }
    }

    fn new_permissive() -> Self {
        Self::new(ParserConfig {
            max_method_length: 256,
            allow_extensions: true,
            enforce_uppercase: false,
        })
    }

    fn new_strict() -> Self {
        Self::new(ParserConfig {
            max_method_length: 64,
            allow_extensions: false,
            enforce_uppercase: true,
        })
    }

    fn new_very_strict() -> Self {
        Self::new(ParserConfig {
            max_method_length: 16,
            allow_extensions: false,
            enforce_uppercase: true,
        })
    }

    fn validate_method(&self, method: &str) -> Result<(), MethodValidationError> {
        // Empty method check
        if method.is_empty() {
            return Err(MethodValidationError::Empty);
        }

        // Length check - this is the primary test
        if method.len() > self.config.max_method_length {
            return Err(MethodValidationError::MethodTooLong {
                length: method.len(),
                max: self.config.max_method_length,
            });
        }

        // ASCII check
        if !method.is_ascii() {
            return Err(MethodValidationError::NonAscii);
        }

        // Control character check
        if method.chars().any(|c| c.is_control()) {
            return Err(MethodValidationError::ControlCharacters);
        }

        // Valid method character check (RFC 9110)
        // Method = token, where token = 1*tchar
        // tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
        //         "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
        for ch in method.chars() {
            if !Self::is_valid_method_char(ch) {
                return Err(MethodValidationError::InvalidCharacters);
            }
        }

        // Case enforcement
        if self.config.enforce_uppercase && method != method.to_uppercase() {
            return Err(MethodValidationError::InvalidCase);
        }

        // Extension method check
        if !self.config.allow_extensions && !Self::is_standard_method(method) {
            return Err(MethodValidationError::UnknownMethod);
        }

        Ok(())
    }

    fn is_valid_method_char(ch: char) -> bool {
        // RFC 9110 tchar
        ch.is_ascii_alphanumeric()
            || matches!(
                ch,
                '!' | '#'
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
                    | '~'
            )
    }

    fn is_standard_method(method: &str) -> bool {
        matches!(
            method.to_uppercase().as_str(),
            "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "TRACE" | "CONNECT"
        )
    }

    fn generate_method(input: &H2MethodLengthInput) -> String {
        match &input.method_strategy {
            MethodStrategy::Standard(std_method) => {
                let base = match std_method {
                    StandardMethod::Get => "GET",
                    StandardMethod::Post => "POST",
                    StandardMethod::Put => "PUT",
                    StandardMethod::Delete => "DELETE",
                    StandardMethod::Head => "HEAD",
                    StandardMethod::Options => "OPTIONS",
                    StandardMethod::Patch => "PATCH",
                    StandardMethod::Trace => "TRACE",
                    StandardMethod::Connect => "CONNECT",
                }
                .to_string();

                Self::apply_properties(base, &input.method_properties)
            }
            MethodStrategy::Extension { name } => {
                Self::apply_properties(name.clone(), &input.method_properties)
            }
            MethodStrategy::Generated { target_length } => {
                let mut method = "X".repeat(*target_length);
                method = Self::apply_properties(method, &input.method_properties);

                // Ensure exact target length if possible
                if method.len() != *target_length && *target_length > 0 {
                    if method.len() < *target_length {
                        method.push_str(&"Y".repeat(*target_length - method.len()));
                    } else {
                        method.truncate(*target_length);
                    }
                }
                method
            }
            MethodStrategy::Padded { base, padding } => {
                let base_str = match base {
                    StandardMethod::Get => "GET",
                    StandardMethod::Post => "POST",
                    StandardMethod::Put => "PUT",
                    StandardMethod::Delete => "DELETE",
                    StandardMethod::Head => "HEAD",
                    StandardMethod::Options => "OPTIONS",
                    StandardMethod::Patch => "PATCH",
                    StandardMethod::Trace => "TRACE",
                    StandardMethod::Connect => "CONNECT",
                };
                let method = format!("{}{}", base_str, padding);
                Self::apply_properties(method, &input.method_properties)
            }
            MethodStrategy::Repeated { character, count } => {
                let method = character.to_string().repeat(*count);
                Self::apply_properties(method, &input.method_properties)
            }
            MethodStrategy::MixedCase { base_method } => {
                let mut method = String::new();
                for (i, ch) in base_method.chars().enumerate() {
                    if i % 2 == 0 {
                        method.push(ch.to_ascii_uppercase());
                    } else {
                        method.push(ch.to_ascii_lowercase());
                    }
                }
                method
            }
        }
    }

    fn apply_properties(mut method: String, props: &MethodProperties) -> String {
        if props.uppercase && !props.lowercase {
            method = method.to_uppercase();
        } else if props.lowercase && !props.uppercase {
            method = method.to_lowercase();
        }

        if props.special_chars && method.len() < 100 {
            method.push_str("-EXT");
        }

        if props.unicode && method.len() < 100 {
            // Add some unicode, but this will likely cause NonAscii error
            method.push('🚀');
        }

        if props.control_chars && method.len() < 100 {
            // Add control character, but this will likely cause ControlCharacters error
            method.push('\x01');
        }

        method
    }

    fn get_target_length(category: &LengthCategory) -> usize {
        match category {
            LengthCategory::VeryShort => 2,
            LengthCategory::Standard => 6,
            LengthCategory::Extension => 12,
            LengthCategory::LongExtension => 48,
            LengthCategory::VeryLong => 128,
            LengthCategory::ExtremelyLong => 512,
            LengthCategory::Boundary(test) => match test {
                BoundaryTest::Around64 { offset } => (64i32 + *offset as i32).max(0) as usize,
                BoundaryTest::Around128 { offset } => (128i32 + *offset as i32).max(0) as usize,
                BoundaryTest::Around256 { offset } => (256i32 + *offset as i32).max(0) as usize,
                BoundaryTest::Around512 { offset } => (512i32 + *offset as i32).max(0) as usize,
                BoundaryTest::Around1024 { offset } => (1024i32 + *offset as i32).max(0) as usize,
            },
        }
    }
}

fuzz_target!(|input: H2MethodLengthInput| {
    // Generate method based on input
    let method = MockH2MethodParser::generate_method(&input);

    // Skip extremely large methods that would cause memory issues
    if method.len() > 10000 {
        return;
    }

    // Test with different parser configurations
    let parsers = [
        ("permissive", MockH2MethodParser::new_permissive()),
        ("strict", MockH2MethodParser::new_strict()),
        ("very_strict", MockH2MethodParser::new_very_strict()),
    ];

    for (parser_name, parser) in &parsers {
        let result = parser.validate_method(&method);

        // Apply fuzzing assertions based on parser type and method characteristics
        match *parser_name {
            "permissive" => {
                // Permissive parser (256 char limit)
                if method.len() > 256 {
                    assert!(matches!(
                        result,
                        Err(MethodValidationError::MethodTooLong { .. })
                    ));
                } else if method.is_empty() {
                    assert!(matches!(result, Err(MethodValidationError::Empty)));
                } else if !method.is_ascii() {
                    assert!(matches!(result, Err(MethodValidationError::NonAscii)));
                } else if method.chars().any(|c| c.is_control()) {
                    assert!(matches!(
                        result,
                        Err(MethodValidationError::ControlCharacters)
                    ));
                } else if method
                    .chars()
                    .any(|c| !MockH2MethodParser::is_valid_method_char(c))
                {
                    assert!(matches!(
                        result,
                        Err(MethodValidationError::InvalidCharacters)
                    ));
                } else {
                    // Should accept valid methods up to 256 characters
                    assert!(
                        result.is_ok(),
                        "Permissive parser rejected valid method: '{}'",
                        method
                    );
                }
            }
            "strict" => {
                // Strict parser (64 char limit, no extensions)
                if method.len() > 64 {
                    assert!(matches!(
                        result,
                        Err(MethodValidationError::MethodTooLong { .. })
                    ));
                } else if method.is_empty() {
                    assert!(matches!(result, Err(MethodValidationError::Empty)));
                } else if !method.is_ascii() {
                    assert!(matches!(result, Err(MethodValidationError::NonAscii)));
                } else if method.chars().any(|c| c.is_control()) {
                    assert!(matches!(
                        result,
                        Err(MethodValidationError::ControlCharacters)
                    ));
                } else if method
                    .chars()
                    .any(|c| !MockH2MethodParser::is_valid_method_char(c))
                {
                    assert!(matches!(
                        result,
                        Err(MethodValidationError::InvalidCharacters)
                    ));
                } else if method != method.to_uppercase() {
                    assert!(matches!(result, Err(MethodValidationError::InvalidCase)));
                } else if !MockH2MethodParser::is_standard_method(&method) {
                    assert!(matches!(result, Err(MethodValidationError::UnknownMethod)));
                } else {
                    // Should accept standard methods in uppercase
                    assert!(
                        result.is_ok(),
                        "Strict parser rejected valid standard method: '{}'",
                        method
                    );
                }
            }
            "very_strict" => {
                // Very strict parser (16 char limit, no extensions, uppercase only)
                if method.len() > 16 {
                    assert!(matches!(
                        result,
                        Err(MethodValidationError::MethodTooLong { .. })
                    ));
                } else if method.is_empty() {
                    assert!(matches!(result, Err(MethodValidationError::Empty)));
                } else if !method.is_ascii() {
                    assert!(matches!(result, Err(MethodValidationError::NonAscii)));
                } else if method.chars().any(|c| c.is_control()) {
                    assert!(matches!(
                        result,
                        Err(MethodValidationError::ControlCharacters)
                    ));
                } else if method
                    .chars()
                    .any(|c| !MockH2MethodParser::is_valid_method_char(c))
                {
                    assert!(matches!(
                        result,
                        Err(MethodValidationError::InvalidCharacters)
                    ));
                } else if method != method.to_uppercase() {
                    assert!(matches!(result, Err(MethodValidationError::InvalidCase)));
                } else if !MockH2MethodParser::is_standard_method(&method) {
                    assert!(matches!(result, Err(MethodValidationError::UnknownMethod)));
                } else {
                    // Should accept standard methods in uppercase under 16 chars
                    // All standard methods are under 16 chars, so this should work
                    assert!(
                        result.is_ok(),
                        "Very strict parser rejected valid standard method: '{}'",
                        method
                    );
                }
            }
            _ => unreachable!(),
        }
    }

    // Test invariants that should hold across all parsers
    test_method_invariants(&method, &input);
});

fn test_method_invariants(method: &str, input: &H2MethodLengthInput) {
    // Invariant: Empty methods must always be rejected
    if method.is_empty() {
        let parser = MockH2MethodParser::new_permissive();
        assert!(matches!(
            parser.validate_method(method),
            Err(MethodValidationError::Empty)
        ));
    }

    // Invariant: Non-ASCII methods must always be rejected
    if !method.is_ascii() {
        let parser = MockH2MethodParser::new_permissive();
        assert!(matches!(
            parser.validate_method(method),
            Err(MethodValidationError::NonAscii)
        ));
    }

    // Invariant: Control characters must always be rejected
    if method.chars().any(|c| c.is_control()) {
        let parser = MockH2MethodParser::new_permissive();
        assert!(matches!(
            parser.validate_method(method),
            Err(MethodValidationError::ControlCharacters)
        ));
    }

    // Invariant: Invalid characters must always be rejected
    if method
        .chars()
        .any(|c| !MockH2MethodParser::is_valid_method_char(c))
    {
        let parser = MockH2MethodParser::new_permissive();
        assert!(matches!(
            parser.validate_method(method),
            Err(MethodValidationError::InvalidCharacters)
        ));
    }

    // Invariant: Extremely long methods (>1024) should be rejected by all parsers
    if method.len() > 1024 {
        for parser in [
            MockH2MethodParser::new_permissive(),
            MockH2MethodParser::new_strict(),
            MockH2MethodParser::new_very_strict(),
        ] {
            assert!(
                parser.validate_method(method).is_err(),
                "Parser should reject method longer than 1024 characters"
            );
        }
    }

    // Invariant: Boundary testing should be consistent
    if let LengthCategory::Boundary(boundary_test) = &input.length_category {
        match boundary_test {
            BoundaryTest::Around64 { offset: _ } => {
                // Methods around 64 characters should be handled consistently
                let strict_parser = MockH2MethodParser::new_strict();
                let result = strict_parser.validate_method(method);

                if method.len() > 64
                    && method.chars().all(MockH2MethodParser::is_valid_method_char)
                    && method.is_ascii()
                {
                    assert!(matches!(
                        result,
                        Err(MethodValidationError::MethodTooLong { .. })
                    ));
                }
            }
            BoundaryTest::Around256 { offset: _ } => {
                // Methods around 256 characters should be handled consistently
                let permissive_parser = MockH2MethodParser::new_permissive();
                let result = permissive_parser.validate_method(method);

                if method.len() > 256
                    && method.chars().all(MockH2MethodParser::is_valid_method_char)
                    && method.is_ascii()
                {
                    assert!(matches!(
                        result,
                        Err(MethodValidationError::MethodTooLong { .. })
                    ));
                }
            }
            _ => {
                // Other boundary tests
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_methods() {
        let parser = MockH2MethodParser::new_permissive();

        for method in [
            "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT",
        ] {
            assert!(
                parser.validate_method(method).is_ok(),
                "Standard method should be valid: {}",
                method
            );
        }
    }

    #[test]
    fn test_method_length_limits() {
        let permissive = MockH2MethodParser::new_permissive();
        let strict = MockH2MethodParser::new_strict();
        let very_strict = MockH2MethodParser::new_very_strict();

        // 64 character method
        let method_64 = "X".repeat(64);
        assert!(permissive.validate_method(&method_64).is_ok());
        assert!(strict.validate_method(&method_64).is_ok());
        assert!(matches!(
            very_strict.validate_method(&method_64),
            Err(MethodValidationError::MethodTooLong { .. })
        ));

        // 65 character method
        let method_65 = "X".repeat(65);
        assert!(permissive.validate_method(&method_65).is_ok());
        assert!(matches!(
            strict.validate_method(&method_65),
            Err(MethodValidationError::MethodTooLong { .. })
        ));
        assert!(matches!(
            very_strict.validate_method(&method_65),
            Err(MethodValidationError::MethodTooLong { .. })
        ));

        // 256 character method
        let method_256 = "X".repeat(256);
        assert!(permissive.validate_method(&method_256).is_ok());
        assert!(matches!(
            strict.validate_method(&method_256),
            Err(MethodValidationError::MethodTooLong { .. })
        ));
        assert!(matches!(
            very_strict.validate_method(&method_256),
            Err(MethodValidationError::MethodTooLong { .. })
        ));

        // 257 character method
        let method_257 = "X".repeat(257);
        assert!(matches!(
            permissive.validate_method(&method_257),
            Err(MethodValidationError::MethodTooLong { .. })
        ));
        assert!(matches!(
            strict.validate_method(&method_257),
            Err(MethodValidationError::MethodTooLong { .. })
        ));
        assert!(matches!(
            very_strict.validate_method(&method_257),
            Err(MethodValidationError::MethodTooLong { .. })
        ));
    }

    #[test]
    fn test_empty_method() {
        let parser = MockH2MethodParser::new_permissive();
        assert!(matches!(
            parser.validate_method(""),
            Err(MethodValidationError::Empty)
        ));
    }

    #[test]
    fn test_invalid_characters() {
        let parser = MockH2MethodParser::new_permissive();

        // Control character
        assert!(matches!(
            parser.validate_method("GET\x01"),
            Err(MethodValidationError::ControlCharacters)
        ));

        // Unicode
        assert!(matches!(
            parser.validate_method("GETé"),
            Err(MethodValidationError::NonAscii)
        ));

        // Invalid tchar
        assert!(matches!(
            parser.validate_method("GET<>"),
            Err(MethodValidationError::InvalidCharacters)
        ));
    }

    #[test]
    fn test_extension_methods() {
        let permissive = MockH2MethodParser::new_permissive();
        let strict = MockH2MethodParser::new_strict();

        let extension_method = "CUSTOMMETHOD";

        assert!(permissive.validate_method(extension_method).is_ok());
        assert!(matches!(
            strict.validate_method(extension_method),
            Err(MethodValidationError::UnknownMethod)
        ));
    }

    #[test]
    fn test_case_sensitivity() {
        let permissive = MockH2MethodParser::new_permissive();
        let strict = MockH2MethodParser::new_strict();

        assert!(permissive.validate_method("get").is_ok());
        assert!(permissive.validate_method("GET").is_ok());

        assert!(strict.validate_method("GET").is_ok());
        assert!(matches!(
            strict.validate_method("get"),
            Err(MethodValidationError::InvalidCase)
        ));
    }

    #[test]
    fn test_boundary_values() {
        let parsers = [
            (MockH2MethodParser::new_very_strict(), 16),
            (MockH2MethodParser::new_strict(), 64),
            (MockH2MethodParser::new_permissive(), 256),
        ];

        for (parser, limit) in parsers {
            // At limit
            let method_at_limit = "X".repeat(limit);
            assert!(parser.validate_method(&method_at_limit).is_ok());

            // One over limit
            let method_over_limit = "X".repeat(limit + 1);
            assert!(matches!(
                parser.validate_method(&method_over_limit),
                Err(MethodValidationError::MethodTooLong { .. })
            ));
        }
    }
}
