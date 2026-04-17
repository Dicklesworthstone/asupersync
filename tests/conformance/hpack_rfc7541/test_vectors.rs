//! RFC 7541 Appendix C test vectors and systematic test cases.

use asupersync::http::h2::hpack::Header;

/// Test vector from RFC 7541 Appendix C.
#[derive(Debug, Clone)]
pub struct Rfc7541TestVector {
    pub id: &'static str,
    pub description: &'static str,
    pub headers: &'static [(&'static str, &'static str)],
    pub expected_encoded: &'static [u8],
    pub use_huffman: bool,
}

/// RFC 7541 Appendix C.1.1: Literal Header Field with Incremental Indexing — New Name
pub const C1_1_LITERAL_NEW_NAME: Rfc7541TestVector = Rfc7541TestVector {
    id: "RFC7541-C.1.1",
    description: "Literal Header Field with Incremental Indexing — New Name",
    headers: &[("custom-key", "custom-header")],
    expected_encoded: &[
        0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79,
        0x0d, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
    ],
    use_huffman: false,
};

/// RFC 7541 Appendix C.1.2: Literal Header Field with Incremental Indexing — Indexed Name
pub const C1_2_LITERAL_INDEXED_NAME: Rfc7541TestVector = Rfc7541TestVector {
    id: "RFC7541-C.1.2",
    description: "Literal Header Field with Incremental Indexing — Indexed Name",
    headers: &[(":path", "/sample/path")],
    expected_encoded: &[
        0x44, 0x0c, 0x2f, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x70, 0x61, 0x74, 0x68,
    ],
    use_huffman: false,
};

/// RFC 7541 Appendix C.1.3: Literal Header Field with Incremental Indexing — Indexed Name
pub const C1_3_LITERAL_INDEXED_NAME_HUFFMAN: Rfc7541TestVector = Rfc7541TestVector {
    id: "RFC7541-C.1.3",
    description: "Literal Header Field with Incremental Indexing — Indexed Name (Huffman)",
    headers: &[(":path", "/sample/path")],
    expected_encoded: &[
        0x44, 0x89, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f,
    ],
    use_huffman: true,
};

/// RFC 7541 Appendix C.2.1: Literal Header Field without Indexing — New Name
pub const C2_1_LITERAL_WITHOUT_INDEXING: Rfc7541TestVector = Rfc7541TestVector {
    id: "RFC7541-C.2.1",
    description: "Literal Header Field without Indexing — New Name",
    headers: &[("password", "secret")],
    expected_encoded: &[
        0x00, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64,
        0x06, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74,
    ],
    use_huffman: false,
};

/// RFC 7541 Appendix C.2.2: Literal Header Field without Indexing — Indexed Name
pub const C2_2_LITERAL_WITHOUT_INDEXING_INDEXED: Rfc7541TestVector = Rfc7541TestVector {
    id: "RFC7541-C.2.2",
    description: "Literal Header Field without Indexing — Indexed Name",
    headers: &[(":path", "/")],
    expected_encoded: &[0x04, 0x01, 0x2f],
    use_huffman: false,
};

/// RFC 7541 Appendix C.2.3: Literal Header Field without Indexing — Indexed Name (Huffman)
pub const C2_3_LITERAL_WITHOUT_INDEXING_HUFFMAN: Rfc7541TestVector = Rfc7541TestVector {
    id: "RFC7541-C.2.3",
    description: "Literal Header Field without Indexing — Indexed Name (Huffman)",
    headers: &[(":path", "/")],
    expected_encoded: &[0x04, 0x81, 0x1c],
    use_huffman: true,
};

/// RFC 7541 Appendix C.3.1: Literal Header Field Never Indexed — New Name
pub const C3_1_LITERAL_NEVER_INDEXED: Rfc7541TestVector = Rfc7541TestVector {
    id: "RFC7541-C.3.1",
    description: "Literal Header Field Never Indexed — New Name",
    headers: &[("password", "secret")],
    expected_encoded: &[
        0x10, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64,
        0x06, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74,
    ],
    use_huffman: false,
};

/// RFC 7541 Appendix C.3.2: Literal Header Field Never Indexed — Indexed Name
pub const C3_2_LITERAL_NEVER_INDEXED_INDEXED: Rfc7541TestVector = Rfc7541TestVector {
    id: "RFC7541-C.3.2",
    description: "Literal Header Field Never Indexed — Indexed Name",
    headers: &[(":path", "/")],
    expected_encoded: &[0x14, 0x01, 0x2f],
    use_huffman: false,
};

/// RFC 7541 Appendix C.3.3: Literal Header Field Never Indexed — Indexed Name (Huffman)
pub const C3_3_LITERAL_NEVER_INDEXED_HUFFMAN: Rfc7541TestVector = Rfc7541TestVector {
    id: "RFC7541-C.3.3",
    description: "Literal Header Field Never Indexed — Indexed Name (Huffman)",
    headers: &[(":path", "/")],
    expected_encoded: &[0x14, 0x81, 0x1c],
    use_huffman: true,
};

/// RFC 7541 Appendix C.4.1: Indexed Header Field
pub const C4_1_INDEXED_HEADER_FIELD: Rfc7541TestVector = Rfc7541TestVector {
    id: "RFC7541-C.4.1",
    description: "Indexed Header Field",
    headers: &[(":method", "GET")],
    expected_encoded: &[0x82],
    use_huffman: false,
};

/// All RFC 7541 Appendix C test vectors.
pub const RFC7541_TEST_VECTORS: &[Rfc7541TestVector] = &[
    C1_1_LITERAL_NEW_NAME,
    C1_2_LITERAL_INDEXED_NAME,
    C1_3_LITERAL_INDEXED_NAME_HUFFMAN,
    C2_1_LITERAL_WITHOUT_INDEXING,
    C2_2_LITERAL_WITHOUT_INDEXING_INDEXED,
    C2_3_LITERAL_WITHOUT_INDEXING_HUFFMAN,
    C3_1_LITERAL_NEVER_INDEXED,
    C3_2_LITERAL_NEVER_INDEXED_INDEXED,
    C3_3_LITERAL_NEVER_INDEXED_HUFFMAN,
    C4_1_INDEXED_HEADER_FIELD,
];

/// Convert test vector headers to Header structs.
pub fn test_vector_to_headers(test_vector: &Rfc7541TestVector) -> Vec<Header> {
    test_vector.headers
        .iter()
        .map(|(name, value)| Header::new(*name, *value))
        .collect()
}

/// Additional systematic test cases beyond RFC Appendix C.
#[derive(Debug, Clone)]
pub struct SystematicTestCase {
    pub id: &'static str,
    pub description: &'static str,
    pub headers: &'static [(&'static str, &'static str)],
    pub test_category: TestCaseCategory,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TestCaseCategory {
    StaticTableHits,
    DynamicTableInteraction,
    LargeHeaders,
    EmptyHeaders,
    SpecialCharacters,
    Unicode,
    EdgeCases,
}

/// Systematic test cases for comprehensive coverage.
pub const SYSTEMATIC_TEST_CASES: &[SystematicTestCase] = &[
    // Static table exact hits
    SystematicTestCase {
        id: "SYS-ST-1",
        description: "All static table exact hits",
        headers: &[
            (":authority", ""),
            (":method", "GET"),
            (":method", "POST"),
            (":path", "/"),
            (":path", "/index.html"),
            (":scheme", "http"),
            (":scheme", "https"),
            (":status", "200"),
            (":status", "404"),
            (":status", "500"),
        ],
        test_category: TestCaseCategory::StaticTableHits,
    },

    // Large header values
    SystematicTestCase {
        id: "SYS-LG-1",
        description: "Large header values",
        headers: &[
            ("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Very Long User Agent String That Exceeds Normal Lengths"),
            ("authorization", "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.Very-Long-JWT-Token-That-Contains-Lots-Of-Claims-And-Data"),
            ("content-length", "1048576"),
        ],
        test_category: TestCaseCategory::LargeHeaders,
    },

    // Empty values
    SystematicTestCase {
        id: "SYS-EM-1",
        description: "Empty header values",
        headers: &[
            ("x-empty", ""),
            ("x-forwarded-for", ""),
            ("accept", ""),
        ],
        test_category: TestCaseCategory::EmptyHeaders,
    },

    // Special characters
    SystematicTestCase {
        id: "SYS-SP-1",
        description: "Special characters in headers",
        headers: &[
            ("x-special", "!@#$%^&*()_+-=[]{}|;:,.<>?"),
            ("x-quotes", "\"quoted value\""),
            ("x-spaces", "  value with spaces  "),
        ],
        test_category: TestCaseCategory::SpecialCharacters,
    },

    // Unicode
    SystematicTestCase {
        id: "SYS-UN-1",
        description: "Unicode in header values",
        headers: &[
            ("x-unicode", "测试 🚀 value"),
            ("x-emoji", "🌟✨🎉"),
            ("x-accents", "café résumé naïve"),
        ],
        test_category: TestCaseCategory::Unicode,
    },

    // Edge cases
    SystematicTestCase {
        id: "SYS-ED-1",
        description: "Edge cases",
        headers: &[
            ("a", "b"),  // Minimal header
            ("x", "b"),  // Simple value for edge case
        ],
        test_category: TestCaseCategory::EdgeCases,
    },
];

/// Convert systematic test case to headers.
pub fn systematic_case_to_headers(test_case: &SystematicTestCase) -> Vec<Header> {
    test_case.headers
        .iter()
        .map(|(name, value)| Header::new(*name, *value))
        .collect()
}

/// Test that validates our test vector data integrity.
#[cfg(test)]
mod test_vector_validation {
    use super::*;

    #[test]
    fn validate_rfc7541_test_vectors_integrity() {
        for vector in RFC7541_TEST_VECTORS {
            // Ensure test vector data is well-formed
            assert!(!vector.id.is_empty(), "Test vector ID must not be empty");
            assert!(!vector.description.is_empty(), "Test vector description must not be empty");
            assert!(!vector.headers.is_empty(), "Test vector must have at least one header");
            assert!(!vector.expected_encoded.is_empty(), "Test vector must have expected encoding");

            // Ensure header names and values are valid
            for (name, value) in vector.headers {
                assert!(!name.is_empty(), "Header name must not be empty");
                // Value can be empty (e.g., ":authority" often is)
            }
        }
    }

    #[test]
    fn validate_systematic_test_cases() {
        for test_case in SYSTEMATIC_TEST_CASES {
            assert!(!test_case.id.is_empty(), "Systematic test case ID must not be empty");
            assert!(!test_case.description.is_empty(), "Description must not be empty");
            assert!(!test_case.headers.is_empty(), "Must have at least one header");
        }
    }
}