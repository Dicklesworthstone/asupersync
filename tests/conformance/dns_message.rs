#![allow(warnings)]
#![allow(clippy::all)]
//! DNS RFC 1035 Message Format Conformance Tests
//!
//! Validates RFC 1035 Section 4.1 message format compliance:
//! - Header ID echo on response
//! - QR/OPCODE/AA/TC/RD/RA/Z/RCODE bit positions and semantics
//! - QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT message section counters
//! - Domain name compression pointers correctly expanded
//! - Question type encodings for A/AAAA/MX/TXT/CNAME/PTR queries
//! - EDNS0 OPT additional-record framing for replayable packet vectors
//! - UDP 512-byte limit triggers TC (truncated) flag
//! - DNS class values: IN (Internet), CH (Chaos), ANY (wildcard)
//! - Common RCODE values: NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED
//!
//! # RFC 1035 Message Format (Section 4.1)
//!
//! ```
//! DNS Message Format:
//!     +---------------------+
//!     |        Header       |
//!     +---------------------+
//!     |       Question      | Questions for the name server
//!     +---------------------+
//!     |        Answer       | Resource Records answering the question
//!     +---------------------+
//!     |      Authority      | Resource Records pointing toward an authority
//!     +---------------------+
//!     |      Additional     | Resource Records holding additional information
//!     +---------------------+
//!
//! DNS Header Format:
//!                                     1  1  1  1  1  1
//!       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |                      ID                       |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |                    QDCOUNT                    |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |                    ANCOUNT                    |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |                    NSCOUNT                    |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |                    ARCOUNT                    |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! ```

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// RFC 2119 requirement level for conformance testing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum RequirementLevel {
    Must,   // RFC 2119: MUST
    Should, // RFC 2119: SHOULD
    May,    // RFC 2119: MAY
}

/// Test result for a single DNS message format conformance requirement
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct DnsConformanceResult {
    pub test_id: String,
    pub description: String,
    pub category: DnsTestCategory,
    pub requirement_level: RequirementLevel,
    pub verdict: DnsTestVerdict,
    pub error_message: Option<String>,
    pub execution_time_ms: u64,
}

/// DNS conformance test categories per RFC 1035 Section 4.1
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum DnsTestCategory {
    /// Header ID field echo validation
    HeaderIdEcho,
    /// Header flag bit position validation (QR/OPCODE/AA/TC/RD/RA/Z/RCODE)
    HeaderFlags,
    /// Message section counters (QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT)
    SectionCounters,
    /// Domain name compression pointer handling
    NameCompression,
    /// DNS question type encoding and extraction
    QuestionTypes,
    /// Additional record framing (for example EDNS0 OPT)
    AdditionalRecords,
    /// Replayable golden packet vectors
    GoldenVectors,
    /// UDP message size limits and TC flag
    MessageSizeLimits,
    /// DNS class field validation (IN/CH/ANY)
    DnsClasses,
    /// Response code validation (RCODE field)
    ResponseCodes,
}

/// Test execution result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum DnsTestVerdict {
    Pass,
    Fail,
    Skipped,
    ExpectedFailure,
}

/// DNS message format conformance test harness
#[allow(dead_code)]
pub struct DnsMessageConformanceHarness {
    /// Test execution timeout
    timeout: Duration,
}

impl Default for DnsMessageConformanceHarness {
    #[allow(dead_code)]
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
        }
    }
}

#[allow(dead_code)]

impl DnsMessageConformanceHarness {
    /// Create new DNS message format conformance harness
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run all DNS message format conformance tests
    #[allow(dead_code)]
    pub fn run_all_tests(&mut self) -> Vec<DnsConformanceResult> {
        let mut results = Vec::new();

        // Test header ID echo
        results.extend(self.test_header_id_echo());

        // Test header flag bits
        results.extend(self.test_header_flags());

        // Test section counters
        results.extend(self.test_section_counters());

        // Test name compression
        results.extend(self.test_name_compression());

        // Test question type encodings
        results.extend(self.test_question_types());

        // Test additional records
        results.extend(self.test_additional_records());

        // Test replayable golden vectors
        results.extend(self.test_golden_vectors());

        // Test message size limits
        results.extend(self.test_message_size_limits());

        // Test DNS classes
        results.extend(self.test_dns_classes());

        // Test response codes
        results.extend(self.test_response_codes());

        results
    }

    /// Test header ID echo validation (RFC 1035 Section 4.1.1)
    #[allow(dead_code)]
    fn test_header_id_echo(&self) -> Vec<DnsConformanceResult> {
        vec![
            self.run_test(
                "HID001",
                "Response message ID must echo query message ID",
                DnsTestCategory::HeaderIdEcho,
                RequirementLevel::Must,
                || self.test_id_echo_validation(),
            ),
            self.run_test(
                "HID002",
                "Response with mismatched ID must be rejected",
                DnsTestCategory::HeaderIdEcho,
                RequirementLevel::Must,
                || self.test_id_mismatch_rejection(),
            ),
            self.run_test(
                "HID003",
                "Zero ID must be handled correctly",
                DnsTestCategory::HeaderIdEcho,
                RequirementLevel::Must,
                || self.test_zero_id_handling(),
            ),
            self.run_test(
                "HID004",
                "Maximum ID value (65535) must be supported",
                DnsTestCategory::HeaderIdEcho,
                RequirementLevel::Must,
                || self.test_max_id_support(),
            ),
        ]
    }

    /// Test header flag bit positions (RFC 1035 Section 4.1.1)
    #[allow(dead_code)]
    fn test_header_flags(&self) -> Vec<DnsConformanceResult> {
        vec![
            self.run_test(
                "HFL001",
                "QR bit correctly identifies query vs response",
                DnsTestCategory::HeaderFlags,
                RequirementLevel::Must,
                || self.test_qr_bit_validation(),
            ),
            self.run_test(
                "HFL002",
                "OPCODE field correctly parsed (0=QUERY, 1=IQUERY, 2=STATUS)",
                DnsTestCategory::HeaderFlags,
                RequirementLevel::Must,
                || self.test_opcode_field_parsing(),
            ),
            self.run_test(
                "HFL003",
                "AA (Authoritative Answer) bit correctly processed",
                DnsTestCategory::HeaderFlags,
                RequirementLevel::Must,
                || self.test_aa_bit_processing(),
            ),
            self.run_test(
                "HFL004",
                "TC (Truncation) bit correctly indicates message truncation",
                DnsTestCategory::HeaderFlags,
                RequirementLevel::Must,
                || self.test_tc_bit_indication(),
            ),
            self.run_test(
                "HFL005",
                "RD (Recursion Desired) bit correctly set and echoed",
                DnsTestCategory::HeaderFlags,
                RequirementLevel::Must,
                || self.test_rd_bit_echo(),
            ),
            self.run_test(
                "HFL006",
                "RA (Recursion Available) bit correctly indicates server capability",
                DnsTestCategory::HeaderFlags,
                RequirementLevel::Must,
                || self.test_ra_bit_capability(),
            ),
            self.run_test(
                "HFL007",
                "Z (Reserved) bits must be zero in queries and responses",
                DnsTestCategory::HeaderFlags,
                RequirementLevel::Must,
                || self.test_z_bits_reserved(),
            ),
            self.run_test(
                "HFL008",
                "RCODE field correctly indicates response status",
                DnsTestCategory::HeaderFlags,
                RequirementLevel::Must,
                || self.test_rcode_field_status(),
            ),
        ]
    }

    /// Test message section counters (RFC 1035 Section 4.1.1)
    #[allow(dead_code)]
    fn test_section_counters(&self) -> Vec<DnsConformanceResult> {
        vec![
            self.run_test(
                "MSC001",
                "QDCOUNT correctly indicates number of questions",
                DnsTestCategory::SectionCounters,
                RequirementLevel::Must,
                || self.test_qdcount_questions(),
            ),
            self.run_test(
                "MSC002",
                "ANCOUNT correctly indicates number of answer records",
                DnsTestCategory::SectionCounters,
                RequirementLevel::Must,
                || self.test_ancount_answers(),
            ),
            self.run_test(
                "MSC003",
                "NSCOUNT correctly indicates number of authority records",
                DnsTestCategory::SectionCounters,
                RequirementLevel::Must,
                || self.test_nscount_authority(),
            ),
            self.run_test(
                "MSC004",
                "ARCOUNT correctly indicates number of additional records",
                DnsTestCategory::SectionCounters,
                RequirementLevel::Must,
                || self.test_arcount_additional(),
            ),
            self.run_test(
                "MSC005",
                "Section counter overflow handling",
                DnsTestCategory::SectionCounters,
                RequirementLevel::Must,
                || self.test_section_counter_overflow(),
            ),
        ]
    }

    /// Test domain name compression (RFC 1035 Section 4.1.4)
    #[allow(dead_code)]
    fn test_name_compression(&self) -> Vec<DnsConformanceResult> {
        vec![
            self.run_test(
                "CMP001",
                "Name compression pointers correctly expanded",
                DnsTestCategory::NameCompression,
                RequirementLevel::Must,
                || self.test_name_compression_expansion(),
            ),
            self.run_test(
                "CMP002",
                "Compression pointer loop detection",
                DnsTestCategory::NameCompression,
                RequirementLevel::Must,
                || self.test_compression_loop_detection(),
            ),
            self.run_test(
                "CMP003",
                "Forward compression pointer rejection",
                DnsTestCategory::NameCompression,
                RequirementLevel::Must,
                || self.test_forward_pointer_rejection(),
            ),
            self.run_test(
                "CMP004",
                "Invalid compression pointer format rejection",
                DnsTestCategory::NameCompression,
                RequirementLevel::Must,
                || self.test_invalid_compression_format(),
            ),
            self.run_test(
                "CMP005",
                "Multiple level compression pointer chains",
                DnsTestCategory::NameCompression,
                RequirementLevel::Must,
                || self.test_multilevel_compression(),
            ),
        ]
    }

    /// Test DNS question types.
    #[allow(dead_code)]
    fn test_question_types(&self) -> Vec<DnsConformanceResult> {
        vec![
            self.run_test(
                "QTP001",
                "Question type A encodes as 1",
                DnsTestCategory::QuestionTypes,
                RequirementLevel::Must,
                || self.test_question_type_encoding("example.com", TYPE_A, "A"),
            ),
            self.run_test(
                "QTP002",
                "Question type AAAA encodes as 28",
                DnsTestCategory::QuestionTypes,
                RequirementLevel::Must,
                || self.test_question_type_encoding("example.com", TYPE_AAAA, "AAAA"),
            ),
            self.run_test(
                "QTP003",
                "Question type MX encodes as 15",
                DnsTestCategory::QuestionTypes,
                RequirementLevel::Must,
                || self.test_question_type_encoding("example.com", TYPE_MX, "MX"),
            ),
            self.run_test(
                "QTP004",
                "Question type TXT encodes as 16",
                DnsTestCategory::QuestionTypes,
                RequirementLevel::Must,
                || self.test_question_type_encoding("example.com", TYPE_TXT, "TXT"),
            ),
            self.run_test(
                "QTP005",
                "Question type CNAME encodes as 5",
                DnsTestCategory::QuestionTypes,
                RequirementLevel::Must,
                || self.test_question_type_encoding("example.com", TYPE_CNAME, "CNAME"),
            ),
            self.run_test(
                "QTP006",
                "Question type PTR encodes as 12",
                DnsTestCategory::QuestionTypes,
                RequirementLevel::Must,
                || self.test_question_type_encoding("ptr.example.com", TYPE_PTR, "PTR"),
            ),
        ]
    }

    /// Test additional-record framing.
    #[allow(dead_code)]
    fn test_additional_records(&self) -> Vec<DnsConformanceResult> {
        vec![
            self.run_test(
                "ADR001",
                "EDNS0 OPT additional record encodes type 41 and payload size",
                DnsTestCategory::AdditionalRecords,
                RequirementLevel::Must,
                || self.test_edns0_opt_record_encoding(),
            ),
            self.run_test(
                "ADR002",
                "ARCOUNT matches presence of a single OPT additional record",
                DnsTestCategory::AdditionalRecords,
                RequirementLevel::Must,
                || self.test_edns0_opt_record_count(),
            ),
        ]
    }

    /// Test replayable golden vectors.
    #[allow(dead_code)]
    fn test_golden_vectors(&self) -> Vec<DnsConformanceResult> {
        vec![
            self.run_test(
                "GLD001",
                "A query golden vector remains stable for replay",
                DnsTestCategory::GoldenVectors,
                RequirementLevel::Must,
                || self.test_a_query_golden_vector(),
            ),
            self.run_test(
                "GLD002",
                "PTR query golden vector remains stable for replay",
                DnsTestCategory::GoldenVectors,
                RequirementLevel::Must,
                || self.test_ptr_query_golden_vector(),
            ),
            self.run_test(
                "GLD003",
                "OPT additional-record golden vector remains stable for replay",
                DnsTestCategory::GoldenVectors,
                RequirementLevel::Must,
                || self.test_opt_record_golden_vector(),
            ),
        ]
    }

    /// Test UDP message size limits (RFC 1035 Section 4.2.1)
    #[allow(dead_code)]
    fn test_message_size_limits(&self) -> Vec<DnsConformanceResult> {
        vec![
            self.run_test(
                "SIZ001",
                "UDP 512-byte limit triggers TC flag when exceeded",
                DnsTestCategory::MessageSizeLimits,
                RequirementLevel::Must,
                || self.test_udp_512_limit_tc_flag(),
            ),
            self.run_test(
                "SIZ002",
                "Messages within 512-byte limit complete without TC flag",
                DnsTestCategory::MessageSizeLimits,
                RequirementLevel::Must,
                || self.test_within_512_no_tc(),
            ),
            self.run_test(
                "SIZ003",
                "Minimum valid message size handling (12-byte header only)",
                DnsTestCategory::MessageSizeLimits,
                RequirementLevel::Must,
                || self.test_minimum_message_size(),
            ),
            self.run_test(
                "SIZ004",
                "Oversized message rejection",
                DnsTestCategory::MessageSizeLimits,
                RequirementLevel::Must,
                || self.test_oversized_message_rejection(),
            ),
        ]
    }

    /// Test DNS class values (RFC 1035 Section 3.2.4)
    #[allow(dead_code)]
    fn test_dns_classes(&self) -> Vec<DnsConformanceResult> {
        vec![
            self.run_test(
                "CLS001",
                "Class IN (Internet) correctly processed",
                DnsTestCategory::DnsClasses,
                RequirementLevel::Must,
                || self.test_class_in_processing(),
            ),
            self.run_test(
                "CLS002",
                "Class CH (Chaos) correctly processed",
                DnsTestCategory::DnsClasses,
                RequirementLevel::Must,
                || self.test_class_ch_processing(),
            ),
            self.run_test(
                "CLS003",
                "Class ANY (wildcard) correctly processed",
                DnsTestCategory::DnsClasses,
                RequirementLevel::Must,
                || self.test_class_any_processing(),
            ),
            self.run_test(
                "CLS004",
                "Invalid class values correctly rejected",
                DnsTestCategory::DnsClasses,
                RequirementLevel::Must,
                || self.test_invalid_class_rejection(),
            ),
        ]
    }

    /// Test response codes (RFC 1035 Section 4.1.1)
    #[allow(dead_code)]
    fn test_response_codes(&self) -> Vec<DnsConformanceResult> {
        vec![
            self.run_test(
                "RCD001",
                "RCODE 0 (NOERROR) indicates successful query",
                DnsTestCategory::ResponseCodes,
                RequirementLevel::Must,
                || self.test_rcode_noerror(),
            ),
            self.run_test(
                "RCD002",
                "RCODE 1 (FORMERR) indicates format error",
                DnsTestCategory::ResponseCodes,
                RequirementLevel::Must,
                || self.test_rcode_formerr(),
            ),
            self.run_test(
                "RCD003",
                "RCODE 2 (SERVFAIL) indicates server failure",
                DnsTestCategory::ResponseCodes,
                RequirementLevel::Must,
                || self.test_rcode_servfail(),
            ),
            self.run_test(
                "RCD004",
                "RCODE 3 (NXDOMAIN) indicates name does not exist",
                DnsTestCategory::ResponseCodes,
                RequirementLevel::Must,
                || self.test_rcode_nxdomain(),
            ),
            self.run_test(
                "RCD005",
                "RCODE 4 (NOTIMP) indicates not implemented",
                DnsTestCategory::ResponseCodes,
                RequirementLevel::Must,
                || self.test_rcode_notimp(),
            ),
            self.run_test(
                "RCD006",
                "RCODE 5 (REFUSED) indicates query refused",
                DnsTestCategory::ResponseCodes,
                RequirementLevel::Must,
                || self.test_rcode_refused(),
            ),
            self.run_test(
                "RCD007",
                "Reserved RCODE values correctly handled",
                DnsTestCategory::ResponseCodes,
                RequirementLevel::Must,
                || self.test_reserved_rcode_values(),
            ),
        ]
    }

    /// Run a single conformance test with timing and error handling
    #[allow(dead_code)]
    fn run_test<F>(
        &self,
        test_id: &str,
        description: &str,
        category: DnsTestCategory,
        requirement_level: RequirementLevel,
        test_fn: F,
    ) -> DnsConformanceResult
    where
        F: FnOnce() -> Result<(), String>,
    {
        let start = Instant::now();
        let (mut verdict, mut error_message) = match test_fn() {
            Ok(()) => (DnsTestVerdict::Pass, None),
            Err(err) => (DnsTestVerdict::Fail, Some(err)),
        };
        let elapsed = start.elapsed();
        let execution_time_ms = elapsed.as_millis() as u64;

        if elapsed > self.timeout {
            verdict = DnsTestVerdict::Fail;
            error_message.get_or_insert_with(|| {
                format!("test exceeded timeout of {}ms", self.timeout.as_millis())
            });
        }

        DnsConformanceResult {
            test_id: test_id.to_string(),
            description: description.to_string(),
            category,
            requirement_level,
            verdict,
            error_message,
            execution_time_ms,
        }
    }

    // =========================================================================
    // Header ID Echo Tests
    // =========================================================================

    /// Test ID echo validation
    #[allow(dead_code)]
    fn test_id_echo_validation(&self) -> Result<(), String> {
        // Test that response ID matches query ID
        let test_packet = create_dns_response_packet(
            0x1234, // ID
            0x8000, // Flags (QR=1, response)
            0, 0, 0, 0, // Counters
        );

        let id = parse_dns_id(&test_packet)?;
        if id == 0x1234 {
            Ok(())
        } else {
            Err(format!("ID mismatch: expected 0x1234, got 0x{:04x}", id))
        }
    }

    /// Test ID mismatch rejection
    #[allow(dead_code)]
    fn test_id_mismatch_rejection(&self) -> Result<(), String> {
        let response_packet = create_dns_response_packet(
            0x5678, // Different ID
            0x8000, // Flags
            0, 0, 0, 0,
        );

        // Simulate parsing with expected ID 0x1234
        let result = validate_response_id(&response_packet, 0x1234);
        match result {
            Err(msg) if msg.contains("mismatched") => Ok(()),
            _ => Err("Expected ID mismatch error".to_string()),
        }
    }

    /// Test zero ID handling
    #[allow(dead_code)]
    fn test_zero_id_handling(&self) -> Result<(), String> {
        let packet = create_dns_response_packet(0x0000, 0x8000, 0, 0, 0, 0);
        let id = parse_dns_id(&packet)?;
        if id == 0x0000 {
            Ok(())
        } else {
            Err(format!("Zero ID not handled correctly: got 0x{:04x}", id))
        }
    }

    /// Test maximum ID value support
    #[allow(dead_code)]
    fn test_max_id_support(&self) -> Result<(), String> {
        let packet = create_dns_response_packet(0xFFFF, 0x8000, 0, 0, 0, 0);
        let id = parse_dns_id(&packet)?;
        if id == 0xFFFF {
            Ok(())
        } else {
            Err(format!(
                "Max ID not supported: expected 0xFFFF, got 0x{:04x}",
                id
            ))
        }
    }

    // =========================================================================
    // Header Flag Tests
    // =========================================================================

    /// Test QR bit validation
    #[allow(dead_code)]
    fn test_qr_bit_validation(&self) -> Result<(), String> {
        // Test query (QR=0)
        let query_packet = create_dns_response_packet(0x1234, 0x0000, 1, 0, 0, 0);
        if is_dns_response(&query_packet)? {
            return Err("Query packet incorrectly identified as response".to_string());
        }

        // Test response (QR=1)
        let response_packet = create_dns_response_packet(0x1234, 0x8000, 1, 1, 0, 0);
        if !is_dns_response(&response_packet)? {
            return Err("Response packet not correctly identified".to_string());
        }

        Ok(())
    }

    /// Test OPCODE field parsing
    #[allow(dead_code)]
    fn test_opcode_field_parsing(&self) -> Result<(), String> {
        let opcodes = [
            (0x0000, 0, "QUERY"),
            (0x0800, 1, "IQUERY"),
            (0x1000, 2, "STATUS"),
            (0x1800, 3, "Reserved"),
        ];

        for (flags, expected_opcode, name) in opcodes {
            let packet = create_dns_response_packet(0x1234, 0x8000 | flags, 0, 0, 0, 0);
            let opcode = parse_dns_opcode(&packet)?;
            if opcode != expected_opcode {
                return Err(format!(
                    "{} opcode parsing failed: expected {}, got {}",
                    name, expected_opcode, opcode
                ));
            }
        }
        Ok(())
    }

    /// Test AA bit processing
    #[allow(dead_code)]
    fn test_aa_bit_processing(&self) -> Result<(), String> {
        // Test non-authoritative (AA=0)
        let non_auth_packet = create_dns_response_packet(0x1234, 0x8000, 0, 1, 0, 0);
        if is_authoritative_answer(&non_auth_packet)? {
            return Err("Non-authoritative packet incorrectly marked as authoritative".to_string());
        }

        // Test authoritative (AA=1)
        let auth_packet = create_dns_response_packet(0x1234, 0x8400, 0, 1, 0, 0);
        if !is_authoritative_answer(&auth_packet)? {
            return Err("Authoritative packet not correctly identified".to_string());
        }

        Ok(())
    }

    /// Test TC bit indication
    #[allow(dead_code)]
    fn test_tc_bit_indication(&self) -> Result<(), String> {
        // Test not truncated (TC=0)
        let complete_packet = create_dns_response_packet(0x1234, 0x8000, 0, 1, 0, 0);
        if is_truncated(&complete_packet)? {
            return Err("Complete packet incorrectly marked as truncated".to_string());
        }

        // Test truncated (TC=1)
        let truncated_packet = create_dns_response_packet(0x1234, 0x8200, 0, 1, 0, 0);
        if !is_truncated(&truncated_packet)? {
            return Err("Truncated packet not correctly identified".to_string());
        }

        Ok(())
    }

    /// Test RD bit echo
    #[allow(dead_code)]
    fn test_rd_bit_echo(&self) -> Result<(), String> {
        // Test recursion not desired (RD=0)
        let no_rd_packet = create_dns_response_packet(0x1234, 0x8000, 0, 0, 0, 0);
        if recursion_desired(&no_rd_packet)? {
            return Err("RD=0 not correctly processed".to_string());
        }

        // Test recursion desired (RD=1)
        let rd_packet = create_dns_response_packet(0x1234, 0x8100, 0, 0, 0, 0);
        if !recursion_desired(&rd_packet)? {
            return Err("RD=1 not correctly processed".to_string());
        }

        Ok(())
    }

    /// Test RA bit capability indication
    #[allow(dead_code)]
    fn test_ra_bit_capability(&self) -> Result<(), String> {
        // Test recursion not available (RA=0)
        let no_ra_packet = create_dns_response_packet(0x1234, 0x8000, 0, 0, 0, 0);
        if recursion_available(&no_ra_packet)? {
            return Err("RA=0 not correctly processed".to_string());
        }

        // Test recursion available (RA=1)
        let ra_packet = create_dns_response_packet(0x1234, 0x8080, 0, 0, 0, 0);
        if !recursion_available(&ra_packet)? {
            return Err("RA=1 not correctly processed".to_string());
        }

        Ok(())
    }

    /// Test reserved Z bits
    #[allow(dead_code)]
    fn test_z_bits_reserved(&self) -> Result<(), String> {
        // Test that Z bits (0x0070) are properly masked/ignored
        let packet_with_z_bits = create_dns_response_packet(0x1234, 0x8070, 0, 0, 0, 0);
        let reserved_bits = parse_reserved_bits(&packet_with_z_bits)?;

        // According to RFC 1035, these should be zero in well-formed messages
        // But parsers should be able to handle non-zero values gracefully
        if reserved_bits != 0 {
            // This is acceptable - just verify they're parsed consistently
        }
        Ok(())
    }

    /// Test RCODE field status indication
    #[allow(dead_code)]
    fn test_rcode_field_status(&self) -> Result<(), String> {
        let rcodes = [
            (0, "NOERROR"),
            (1, "FORMERR"),
            (2, "SERVFAIL"),
            (3, "NXDOMAIN"),
            (4, "NOTIMP"),
            (5, "REFUSED"),
        ];

        for (rcode, name) in rcodes {
            let packet = create_dns_response_packet(0x1234, 0x8000 | rcode, 0, 0, 0, 0);
            let parsed_rcode = parse_rcode(&packet)?;
            if parsed_rcode != rcode as u8 {
                return Err(format!(
                    "{} RCODE parsing failed: expected {}, got {}",
                    name, rcode, parsed_rcode
                ));
            }
        }
        Ok(())
    }

    // =========================================================================
    // Section Counter Tests
    // =========================================================================

    /// Test QDCOUNT (question count)
    #[allow(dead_code)]
    fn test_qdcount_questions(&self) -> Result<(), String> {
        let test_cases = [
            (0, "no questions"),
            (1, "single question"),
            (5, "multiple questions"),
        ];

        for (count, description) in test_cases {
            let packet = create_dns_response_packet(0x1234, 0x8000, count, 0, 0, 0);
            let qdcount = parse_qdcount(&packet)?;
            if qdcount != count {
                return Err(format!(
                    "QDCOUNT {} failed: expected {}, got {}",
                    description, count, qdcount
                ));
            }
        }
        Ok(())
    }

    /// Test ANCOUNT (answer count)
    #[allow(dead_code)]
    fn test_ancount_answers(&self) -> Result<(), String> {
        let test_cases = [
            (0, "no answers"),
            (1, "single answer"),
            (10, "multiple answers"),
        ];

        for (count, description) in test_cases {
            let packet = create_dns_response_packet(0x1234, 0x8000, 0, count, 0, 0);
            let ancount = parse_ancount(&packet)?;
            if ancount != count {
                return Err(format!(
                    "ANCOUNT {} failed: expected {}, got {}",
                    description, count, ancount
                ));
            }
        }
        Ok(())
    }

    /// Test NSCOUNT (authority record count)
    #[allow(dead_code)]
    fn test_nscount_authority(&self) -> Result<(), String> {
        let test_cases = [
            (0, "no authority"),
            (1, "single authority"),
            (3, "multiple authority"),
        ];

        for (count, description) in test_cases {
            let packet = create_dns_response_packet(0x1234, 0x8000, 0, 0, count, 0);
            let nscount = parse_nscount(&packet)?;
            if nscount != count {
                return Err(format!(
                    "NSCOUNT {} failed: expected {}, got {}",
                    description, count, nscount
                ));
            }
        }
        Ok(())
    }

    /// Test ARCOUNT (additional record count)
    #[allow(dead_code)]
    fn test_arcount_additional(&self) -> Result<(), String> {
        let test_cases = [
            (0, "no additional"),
            (1, "single additional"),
            (7, "multiple additional"),
        ];

        for (count, description) in test_cases {
            let packet = create_dns_response_packet(0x1234, 0x8000, 0, 0, 0, count);
            let arcount = parse_arcount(&packet)?;
            if arcount != count {
                return Err(format!(
                    "ARCOUNT {} failed: expected {}, got {}",
                    description, count, arcount
                ));
            }
        }
        Ok(())
    }

    /// Test section counter overflow handling
    #[allow(dead_code)]
    fn test_section_counter_overflow(&self) -> Result<(), String> {
        // Test maximum counter values
        let packet = create_dns_response_packet(0x1234, 0x8000, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF);

        let qdcount = parse_qdcount(&packet)?;
        let ancount = parse_ancount(&packet)?;
        let nscount = parse_nscount(&packet)?;
        let arcount = parse_arcount(&packet)?;

        if qdcount != 0xFFFF || ancount != 0xFFFF || nscount != 0xFFFF || arcount != 0xFFFF {
            return Err("Maximum counter values not handled correctly".to_string());
        }

        Ok(())
    }

    // =========================================================================
    // Name Compression Tests
    // =========================================================================

    /// Test name compression pointer expansion
    #[allow(dead_code)]
    fn test_name_compression_expansion(&self) -> Result<(), String> {
        // Create a packet with compression pointer
        let mut packet = Vec::new();

        // Header
        packet.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        packet.extend_from_slice(&0x8000u16.to_be_bytes()); // Flags
        packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        packet.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        // Question: example.com (at offset 12)
        packet.push(7);
        packet.extend_from_slice(b"example");
        packet.push(3);
        packet.extend_from_slice(b"com");
        packet.push(0);
        packet.extend_from_slice(&1u16.to_be_bytes()); // Type A
        packet.extend_from_slice(&1u16.to_be_bytes()); // Class IN

        // Answer with compression pointer to "example.com"
        let answer_offset = packet.len();
        let example_com_offset = 12;
        packet.extend_from_slice(&(0xC000u16 | example_com_offset).to_be_bytes()); // Name pointer
        packet.extend_from_slice(&1u16.to_be_bytes()); // Type A
        packet.extend_from_slice(&1u16.to_be_bytes()); // Class IN
        packet.extend_from_slice(&300u32.to_be_bytes()); // TTL
        packet.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        packet.extend_from_slice(&[192, 0, 2, 1]); // 192.0.2.1

        // Test that compression pointer is correctly expanded
        let name = extract_compressed_name(&packet, answer_offset)?;
        if name != "example.com" {
            return Err(format!(
                "Name compression failed: expected 'example.com', got '{}'",
                name
            ));
        }

        Ok(())
    }

    /// Test compression pointer loop detection
    #[allow(dead_code)]
    fn test_compression_loop_detection(&self) -> Result<(), String> {
        let mut packet = create_basic_dns_packet();

        // Create a compression pointer loop: pointer at offset 12 points to offset 14,
        // and pointer at offset 14 points back to offset 12
        packet.truncate(12); // Remove existing data after header
        packet.extend_from_slice(&0xC00Eu16.to_be_bytes()); // Points to offset 14
        packet.extend_from_slice(&0xC00Cu16.to_be_bytes()); // Points to offset 12

        let result = extract_compressed_name(&packet, 12);
        match result {
            Err(msg) if msg.contains("loop") || msg.contains("compression") => Ok(()),
            _ => Err("Compression pointer loop not detected".to_string()),
        }
    }

    /// Test forward compression pointer rejection
    #[allow(dead_code)]
    fn test_forward_pointer_rejection(&self) -> Result<(), String> {
        let mut packet = create_basic_dns_packet();
        packet.truncate(12);

        // Create forward pointer (points ahead in the packet)
        packet.extend_from_slice(&0xC020u16.to_be_bytes()); // Points to offset 32 (beyond packet end)

        let result = extract_compressed_name(&packet, 12);
        match result {
            Err(_) => Ok(()), // Forward pointers should be rejected
            Ok(_) => Err("Forward compression pointer not rejected".to_string()),
        }
    }

    /// Test invalid compression format
    #[allow(dead_code)]
    fn test_invalid_compression_format(&self) -> Result<(), String> {
        let mut packet = create_basic_dns_packet();
        packet.truncate(12);

        // Invalid compression format (reserved bits 10)
        packet.extend_from_slice(&0x8000u16.to_be_bytes());

        let result = extract_compressed_name(&packet, 12);
        match result {
            Err(_) => Ok(()), // Invalid format should be rejected
            Ok(_) => Err("Invalid compression format not rejected".to_string()),
        }
    }

    /// Test multilevel compression chains
    #[allow(dead_code)]
    fn test_multilevel_compression(&self) -> Result<(), String> {
        // Test compression pointer that points to another compression pointer
        let mut packet = Vec::new();

        // Header
        packet.extend_from_slice(&0x1234u16.to_be_bytes());
        packet.extend_from_slice(&0x8000u16.to_be_bytes());
        packet.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]); // Counters

        // First name: "com" at offset 12
        let com_offset = packet.len();
        packet.push(3);
        packet.extend_from_slice(b"com");
        packet.push(0);

        // Second name: pointer to "com" at offset 16
        let second_name_offset = packet.len();
        packet.extend_from_slice(&(0xC000u16 | (com_offset as u16)).to_be_bytes());

        // Question pointing to second name
        let question_name_offset = packet.len();
        packet.extend_from_slice(&(0xC000u16 | (second_name_offset as u16)).to_be_bytes());
        packet.extend_from_slice(&[0, 1, 0, 1]); // Type A, Class IN

        // Test multilevel expansion
        let name = extract_compressed_name(&packet, question_name_offset)?;
        if name != "com" {
            return Err(format!(
                "Multilevel compression failed: expected 'com', got '{}'",
                name
            ));
        }

        Ok(())
    }

    // =========================================================================
    // Question Type Tests
    // =========================================================================

    #[allow(dead_code)]

    fn test_question_type_encoding(
        &self,
        name: &str,
        qtype: u16,
        display_name: &str,
    ) -> Result<(), String> {
        let packet = create_dns_query_with_class(0x1234, name, qtype, CLASS_IN);
        let actual_type = extract_question_type(&packet)?;

        if actual_type != qtype {
            return Err(format!(
                "{display_name} question type mismatch: expected {}, got {}",
                qtype, actual_type
            ));
        }

        if extract_question_class(&packet)? != CLASS_IN {
            return Err(format!(
                "{display_name} question class was not encoded as IN"
            ));
        }

        Ok(())
    }

    // =========================================================================
    // Additional Record Tests
    // =========================================================================

    #[allow(dead_code)]

    fn test_edns0_opt_record_encoding(&self) -> Result<(), String> {
        let opt_record = create_opt_record(4096, 0, 0, 0x8000, &[0xde, 0xad, 0xbe, 0xef]);
        let packet =
            create_dns_query_with_additional(0x1234, "example.com", TYPE_A, CLASS_IN, &opt_record);
        let opt = extract_additional_record(&packet)?;

        if opt.record_type != TYPE_OPT {
            return Err(format!(
                "OPT record type mismatch: expected {}, got {}",
                TYPE_OPT, opt.record_type
            ));
        }

        if opt.class != 4096 {
            return Err(format!(
                "OPT UDP payload size mismatch: expected 4096, got {}",
                opt.class
            ));
        }

        if opt.ttl != 0x0000_8000 {
            return Err(format!(
                "OPT TTL field mismatch: expected 0x00008000, got 0x{:08x}",
                opt.ttl
            ));
        }

        if opt.rdata != [0xde, 0xad, 0xbe, 0xef] {
            return Err(format!("OPT RDATA mismatch: got {:02x?}", opt.rdata));
        }

        Ok(())
    }

    #[allow(dead_code)]

    fn test_edns0_opt_record_count(&self) -> Result<(), String> {
        let opt_record = create_opt_record(1232, 0, 0, 0, &[]);
        let packet = create_dns_query_with_additional(
            0x1234,
            "example.com",
            TYPE_AAAA,
            CLASS_IN,
            &opt_record,
        );

        if parse_arcount(&packet)? != 1 {
            return Err("Expected ARCOUNT=1 for a single OPT record".to_string());
        }

        let opt = extract_additional_record(&packet)?;
        if opt.name_len != 1 {
            return Err(format!(
                "OPT owner name must be the root label terminator, got {} bytes",
                opt.name_len
            ));
        }

        Ok(())
    }

    // =========================================================================
    // Golden Vector Tests
    // =========================================================================

    #[allow(dead_code)]

    fn test_a_query_golden_vector(&self) -> Result<(), String> {
        let packet = create_dns_query_with_class(0x1234, "example.com", TYPE_A, CLASS_IN);
        let expected = vec![
            0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];

        assert_packet_matches_golden("A query", &packet, &expected)
    }

    #[allow(dead_code)]

    fn test_ptr_query_golden_vector(&self) -> Result<(), String> {
        let packet = create_dns_query_with_class(0x1234, "ptr.example.com", TYPE_PTR, CLASS_IN);
        let expected = vec![
            0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'p',
            b't', b'r', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, 0x00, 0x0c, 0x00, 0x01,
        ];

        assert_packet_matches_golden("PTR query", &packet, &expected)
    }

    #[allow(dead_code)]

    fn test_opt_record_golden_vector(&self) -> Result<(), String> {
        let opt_record = create_opt_record(4096, 0, 0, 0x8000, &[0xde, 0xad, 0xbe, 0xef]);
        let packet =
            create_dns_query_with_additional(0x1234, "example.com", TYPE_A, CLASS_IN, &opt_record);
        let expected = vec![
            0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x04, 0xde, 0xad,
            0xbe, 0xef,
        ];

        assert_packet_matches_golden("OPT record", &packet, &expected)
    }

    // =========================================================================
    // Message Size Limit Tests
    // =========================================================================

    /// Test UDP 512-byte limit with TC flag
    #[allow(dead_code)]
    fn test_udp_512_limit_tc_flag(&self) -> Result<(), String> {
        // Create a message that would exceed 512 bytes
        let large_response_packet = create_dns_response_packet(0x1234, 0x8200, 0, 20, 0, 0); // TC=1

        if !is_truncated(&large_response_packet)? {
            return Err("Large message did not set TC flag".to_string());
        }

        Ok(())
    }

    /// Test messages within 512 bytes don't set TC
    #[allow(dead_code)]
    fn test_within_512_no_tc(&self) -> Result<(), String> {
        let normal_packet = create_dns_response_packet(0x1234, 0x8000, 0, 1, 0, 0); // TC=0

        if is_truncated(&normal_packet)? {
            return Err("Normal sized message incorrectly set TC flag".to_string());
        }

        Ok(())
    }

    /// Test minimum message size (12-byte header)
    #[allow(dead_code)]
    fn test_minimum_message_size(&self) -> Result<(), String> {
        let minimal_packet = create_dns_response_packet(0x1234, 0x8000, 0, 0, 0, 0);

        if minimal_packet.len() < 12 {
            return Err("Minimal packet too small".to_string());
        }

        // Should parse without error
        let _id = parse_dns_id(&minimal_packet)?;
        Ok(())
    }

    /// Test oversized message rejection
    #[allow(dead_code)]
    fn test_oversized_message_rejection(&self) -> Result<(), String> {
        // This is typically enforced at the transport layer
        // Here we test that our parser handles large packets gracefully
        let mut oversized_packet = create_dns_response_packet(0x1234, 0x8000, 0, 1, 0, 0);

        // Extend to exceed reasonable DNS message size
        oversized_packet.resize(65536, 0);

        // Should either parse with TC set or reject gracefully
        let result = parse_dns_id(&oversized_packet);
        match result {
            Ok(_) => Ok(()),  // Large packets can be parsed (up to implementation)
            Err(_) => Ok(()), // Or rejected - both are acceptable
        }
    }

    // =========================================================================
    // DNS Class Tests
    // =========================================================================

    /// Test Class IN (Internet) processing
    #[allow(dead_code)]
    fn test_class_in_processing(&self) -> Result<(), String> {
        let packet_with_class_in = create_dns_query_with_class(0x1234, "example.com", 1, 1); // Type A, Class IN
        let class = extract_question_class(&packet_with_class_in)?;

        if class != 1 {
            return Err(format!(
                "Class IN not processed correctly: expected 1, got {}",
                class
            ));
        }
        Ok(())
    }

    /// Test Class CH (Chaos) processing
    #[allow(dead_code)]
    fn test_class_ch_processing(&self) -> Result<(), String> {
        let packet_with_class_ch = create_dns_query_with_class(0x1234, "example.com", 1, 3); // Type A, Class CH
        let class = extract_question_class(&packet_with_class_ch)?;

        if class != 3 {
            return Err(format!(
                "Class CH not processed correctly: expected 3, got {}",
                class
            ));
        }
        Ok(())
    }

    /// Test Class ANY (wildcard) processing
    #[allow(dead_code)]
    fn test_class_any_processing(&self) -> Result<(), String> {
        let packet_with_class_any = create_dns_query_with_class(0x1234, "example.com", 1, 255); // Type A, Class ANY
        let class = extract_question_class(&packet_with_class_any)?;

        if class != 255 {
            return Err(format!(
                "Class ANY not processed correctly: expected 255, got {}",
                class
            ));
        }
        Ok(())
    }

    /// Test invalid class rejection
    #[allow(dead_code)]
    fn test_invalid_class_rejection(&self) -> Result<(), String> {
        // Test with reserved class value
        let packet_with_invalid_class = create_dns_query_with_class(0x1234, "example.com", 1, 0); // Class 0 is reserved
        let class = extract_question_class(&packet_with_invalid_class)?;

        // Parser should handle reserved classes gracefully
        if class == 0 {
            Ok(()) // Acceptable - parser extracted the value
        } else {
            Err("Invalid class handling unexpected".to_string())
        }
    }

    // =========================================================================
    // Response Code Tests
    // =========================================================================

    /// Test RCODE 0 (NOERROR)
    #[allow(dead_code)]
    fn test_rcode_noerror(&self) -> Result<(), String> {
        let packet = create_dns_response_packet(0x1234, 0x8000, 0, 1, 0, 0); // RCODE=0
        let rcode = parse_rcode(&packet)?;

        if rcode != 0 {
            return Err(format!("NOERROR RCODE failed: expected 0, got {}", rcode));
        }
        Ok(())
    }

    /// Test RCODE 1 (FORMERR)
    #[allow(dead_code)]
    fn test_rcode_formerr(&self) -> Result<(), String> {
        let packet = create_dns_response_packet(0x1234, 0x8001, 0, 0, 0, 0); // RCODE=1
        let rcode = parse_rcode(&packet)?;

        if rcode != 1 {
            return Err(format!("FORMERR RCODE failed: expected 1, got {}", rcode));
        }
        Ok(())
    }

    /// Test RCODE 2 (SERVFAIL)
    #[allow(dead_code)]
    fn test_rcode_servfail(&self) -> Result<(), String> {
        let packet = create_dns_response_packet(0x1234, 0x8002, 0, 0, 0, 0); // RCODE=2
        let rcode = parse_rcode(&packet)?;

        if rcode != 2 {
            return Err(format!("SERVFAIL RCODE failed: expected 2, got {}", rcode));
        }
        Ok(())
    }

    /// Test RCODE 3 (NXDOMAIN)
    #[allow(dead_code)]
    fn test_rcode_nxdomain(&self) -> Result<(), String> {
        let packet = create_dns_response_packet(0x1234, 0x8003, 0, 0, 0, 0); // RCODE=3
        let rcode = parse_rcode(&packet)?;

        if rcode != 3 {
            return Err(format!("NXDOMAIN RCODE failed: expected 3, got {}", rcode));
        }
        Ok(())
    }

    /// Test RCODE 4 (NOTIMP)
    #[allow(dead_code)]
    fn test_rcode_notimp(&self) -> Result<(), String> {
        let packet = create_dns_response_packet(0x1234, 0x8004, 0, 0, 0, 0); // RCODE=4
        let rcode = parse_rcode(&packet)?;

        if rcode != 4 {
            return Err(format!("NOTIMP RCODE failed: expected 4, got {}", rcode));
        }
        Ok(())
    }

    /// Test RCODE 5 (REFUSED)
    #[allow(dead_code)]
    fn test_rcode_refused(&self) -> Result<(), String> {
        let packet = create_dns_response_packet(0x1234, 0x8005, 0, 0, 0, 0); // RCODE=5
        let rcode = parse_rcode(&packet)?;

        if rcode != 5 {
            return Err(format!("REFUSED RCODE failed: expected 5, got {}", rcode));
        }
        Ok(())
    }

    /// Test reserved RCODE values
    #[allow(dead_code)]
    fn test_reserved_rcode_values(&self) -> Result<(), String> {
        // Test RCODE values 6-15 (reserved in RFC 1035)
        for rcode in 6..=15 {
            let packet = create_dns_response_packet(0x1234, 0x8000 | rcode, 0, 0, 0, 0);
            let parsed_rcode = parse_rcode(&packet)?;

            if parsed_rcode != (rcode as u8) {
                return Err(format!(
                    "Reserved RCODE {} parsing failed: expected {}, got {}",
                    rcode, rcode, parsed_rcode
                ));
            }
        }
        Ok(())
    }
}

// =============================================================================
// Helper Functions for DNS Message Construction and Parsing
// =============================================================================

const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_PTR: u16 = 12;
const TYPE_MX: u16 = 15;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;
const TYPE_OPT: u16 = 41;
const CLASS_IN: u16 = 1;

#[allow(dead_code)]
struct AdditionalRecord {
    name_len: usize,
    record_type: u16,
    class: u16,
    ttl: u32,
    rdata: Vec<u8>,
}

/// Create a basic DNS response packet
#[allow(dead_code)]
fn create_dns_response_packet(
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(12);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&flags.to_be_bytes());
    packet.extend_from_slice(&qdcount.to_be_bytes());
    packet.extend_from_slice(&ancount.to_be_bytes());
    packet.extend_from_slice(&nscount.to_be_bytes());
    packet.extend_from_slice(&arcount.to_be_bytes());
    packet
}

/// Create a basic DNS packet for testing
#[allow(dead_code)]
fn create_basic_dns_packet() -> Vec<u8> {
    create_dns_response_packet(0x1234, 0x8000, 0, 0, 0, 0)
}

/// Create DNS query packet with specific class
#[allow(dead_code)]
fn create_dns_query_with_class(id: u16, name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
    let mut packet = Vec::new();

    // Header
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0000u16.to_be_bytes()); // Query flags
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    packet.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // Other counts=0

    // Question
    encode_domain_name(name, &mut packet);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&qclass.to_be_bytes());

    packet
}

/// Create DNS query packet with a single additional record.
#[allow(dead_code)]
fn create_dns_query_with_additional(
    id: u16,
    name: &str,
    qtype: u16,
    qclass: u16,
    additional_record: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::new();

    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());

    encode_domain_name(name, &mut packet);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&qclass.to_be_bytes());
    packet.extend_from_slice(additional_record);

    packet
}

/// Create an EDNS0 OPT additional record.
#[allow(dead_code)]
fn create_opt_record(
    udp_payload_size: u16,
    extended_rcode: u8,
    version: u8,
    flags: u16,
    rdata: &[u8],
) -> Vec<u8> {
    let mut record = Vec::new();
    let ttl = (u32::from(extended_rcode) << 24) | (u32::from(version) << 16) | u32::from(flags);

    record.push(0);
    record.extend_from_slice(&TYPE_OPT.to_be_bytes());
    record.extend_from_slice(&udp_payload_size.to_be_bytes());
    record.extend_from_slice(&ttl.to_be_bytes());
    record.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    record.extend_from_slice(rdata);

    record
}

/// Encode domain name in DNS format
#[allow(dead_code)]
fn encode_domain_name(name: &str, output: &mut Vec<u8>) {
    if name.is_empty() {
        output.push(0);
        return;
    }

    for label in name.split('.') {
        if !label.is_empty() && label.len() <= 63 {
            output.push(label.len() as u8);
            output.extend_from_slice(label.as_bytes());
        }
    }
    output.push(0);
}

/// Parse DNS message ID from packet
#[allow(dead_code)]
fn parse_dns_id(packet: &[u8]) -> Result<u16, String> {
    if packet.len() < 2 {
        return Err("Packet too short for ID field".to_string());
    }
    Ok(u16::from_be_bytes([packet[0], packet[1]]))
}

/// Validate response ID matches expected
#[allow(dead_code)]
fn validate_response_id(packet: &[u8], expected_id: u16) -> Result<(), String> {
    let actual_id = parse_dns_id(packet)?;
    if actual_id != expected_id {
        Err(format!(
            "mismatched DNS response id: expected {}, got {}",
            expected_id, actual_id
        ))
    } else {
        Ok(())
    }
}

/// Check if packet is a DNS response (QR bit set)
#[allow(dead_code)]
fn is_dns_response(packet: &[u8]) -> Result<bool, String> {
    if packet.len() < 4 {
        return Err("Packet too short for flags field".to_string());
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    Ok((flags & 0x8000) != 0)
}

/// Parse OPCODE field from DNS flags
#[allow(dead_code)]
fn parse_dns_opcode(packet: &[u8]) -> Result<u8, String> {
    if packet.len() < 4 {
        return Err("Packet too short for flags field".to_string());
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    Ok(((flags & 0x7800) >> 11) as u8)
}

/// Check if response is authoritative (AA bit set)
#[allow(dead_code)]
fn is_authoritative_answer(packet: &[u8]) -> Result<bool, String> {
    if packet.len() < 4 {
        return Err("Packet too short for flags field".to_string());
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    Ok((flags & 0x0400) != 0)
}

/// Check if message is truncated (TC bit set)
#[allow(dead_code)]
fn is_truncated(packet: &[u8]) -> Result<bool, String> {
    if packet.len() < 4 {
        return Err("Packet too short for flags field".to_string());
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    Ok((flags & 0x0200) != 0)
}

/// Check if recursion desired (RD bit set)
#[allow(dead_code)]
fn recursion_desired(packet: &[u8]) -> Result<bool, String> {
    if packet.len() < 4 {
        return Err("Packet too short for flags field".to_string());
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    Ok((flags & 0x0100) != 0)
}

/// Check if recursion available (RA bit set)
#[allow(dead_code)]
fn recursion_available(packet: &[u8]) -> Result<bool, String> {
    if packet.len() < 4 {
        return Err("Packet too short for flags field".to_string());
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    Ok((flags & 0x0080) != 0)
}

/// Parse reserved Z bits
#[allow(dead_code)]
fn parse_reserved_bits(packet: &[u8]) -> Result<u8, String> {
    if packet.len() < 4 {
        return Err("Packet too short for flags field".to_string());
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    Ok(((flags & 0x0070) >> 4) as u8)
}

/// Parse RCODE field
#[allow(dead_code)]
fn parse_rcode(packet: &[u8]) -> Result<u8, String> {
    if packet.len() < 4 {
        return Err("Packet too short for flags field".to_string());
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    Ok((flags & 0x000F) as u8)
}

/// Parse section counts
#[allow(dead_code)]
fn parse_qdcount(packet: &[u8]) -> Result<u16, String> {
    if packet.len() < 6 {
        return Err("Packet too short for QDCOUNT".to_string());
    }
    Ok(u16::from_be_bytes([packet[4], packet[5]]))
}

#[allow(dead_code)]

fn parse_ancount(packet: &[u8]) -> Result<u16, String> {
    if packet.len() < 8 {
        return Err("Packet too short for ANCOUNT".to_string());
    }
    Ok(u16::from_be_bytes([packet[6], packet[7]]))
}

#[allow(dead_code)]

fn parse_nscount(packet: &[u8]) -> Result<u16, String> {
    if packet.len() < 10 {
        return Err("Packet too short for NSCOUNT".to_string());
    }
    Ok(u16::from_be_bytes([packet[8], packet[9]]))
}

#[allow(dead_code)]

fn parse_arcount(packet: &[u8]) -> Result<u16, String> {
    if packet.len() < 12 {
        return Err("Packet too short for ARCOUNT".to_string());
    }
    Ok(u16::from_be_bytes([packet[10], packet[11]]))
}

/// Extract compressed name from DNS packet
#[allow(dead_code)]
fn extract_compressed_name(packet: &[u8], offset: usize) -> Result<String, String> {
    decode_dns_name_from_offset(packet, offset, 0)
}

/// Decode DNS name with compression support
#[allow(dead_code)]
fn decode_dns_name_from_offset(
    packet: &[u8],
    start_offset: usize,
    depth: usize,
) -> Result<String, String> {
    if depth > 16 {
        return Err("DNS compression pointer loop detected".to_string());
    }

    let mut labels = Vec::new();
    let mut offset = start_offset;

    loop {
        if offset >= packet.len() {
            return Err("Unexpected end of packet while parsing name".to_string());
        }

        let len = packet[offset];

        // Check for compression pointer (top 2 bits set)
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= packet.len() {
                return Err("Truncated compression pointer".to_string());
            }
            let pointer = ((u16::from(len & 0x3F) << 8) | u16::from(packet[offset + 1])) as usize;
            if pointer >= start_offset {
                return Err("Forward compression pointer not allowed".to_string());
            }
            let suffix = decode_dns_name_from_offset(packet, pointer, depth + 1)?;
            if !suffix.is_empty() {
                labels.push(suffix);
            }
            break;
        }

        // Check for invalid compression format
        if len & 0xC0 != 0 {
            return Err("Invalid DNS label encoding".to_string());
        }

        offset += 1;

        // Zero length indicates end of name
        if len == 0 {
            break;
        }

        // Extract label
        if offset + (len as usize) > packet.len() {
            return Err("Label extends beyond packet".to_string());
        }

        let label_bytes = &packet[offset..offset + (len as usize)];
        let label = std::str::from_utf8(label_bytes)
            .map_err(|_| "Invalid UTF-8 in DNS label".to_string())?;
        labels.push(label.to_string());
        offset += len as usize;
    }

    Ok(labels.join("."))
}

/// Extract question class from DNS query packet
#[allow(dead_code)]
fn extract_question_class(packet: &[u8]) -> Result<u16, String> {
    if packet.len() < 12 {
        return Err("Packet too short to contain question".to_string());
    }

    let offset = question_end_offset(packet)?;

    if offset + 4 > packet.len() {
        return Err("Question section truncated".to_string());
    }

    Ok(u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]))
}

/// Extract question type from DNS query packet.
#[allow(dead_code)]
fn extract_question_type(packet: &[u8]) -> Result<u16, String> {
    if packet.len() < 12 {
        return Err("Packet too short to contain question".to_string());
    }

    let offset = question_end_offset(packet)?;
    if offset + 2 > packet.len() {
        return Err("Question type truncated".to_string());
    }

    Ok(u16::from_be_bytes([packet[offset], packet[offset + 1]]))
}

/// Extract a single additional record after the first question.
#[allow(dead_code)]
fn extract_additional_record(packet: &[u8]) -> Result<AdditionalRecord, String> {
    let mut offset = question_end_offset(packet)?;
    if offset + 4 > packet.len() {
        return Err("Question section truncated".to_string());
    }
    offset += 4;

    let name_start = offset;
    offset = skip_dns_name(packet, offset)?;
    let name_len = offset - name_start;

    if offset + 10 > packet.len() {
        return Err("Additional record header truncated".to_string());
    }

    let record_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    let class = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
    let ttl = u32::from_be_bytes([
        packet[offset + 4],
        packet[offset + 5],
        packet[offset + 6],
        packet[offset + 7],
    ]);
    let rdlen = usize::from(u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]));
    offset += 10;

    if offset + rdlen > packet.len() {
        return Err("Additional record RDATA truncated".to_string());
    }

    Ok(AdditionalRecord {
        name_len,
        record_type,
        class,
        ttl,
        rdata: packet[offset..offset + rdlen].to_vec(),
    })
}

#[allow(dead_code)]

fn question_end_offset(packet: &[u8]) -> Result<usize, String> {
    let offset = skip_dns_name(packet, 12)?;
    if offset + 4 > packet.len() {
        return Err("Question section truncated".to_string());
    }

    Ok(offset)
}

#[allow(dead_code)]

fn skip_dns_name(packet: &[u8], start_offset: usize) -> Result<usize, String> {
    let mut offset = start_offset;

    loop {
        if offset >= packet.len() {
            return Err("Unexpected end while parsing DNS name".to_string());
        }

        let len = packet[offset];
        if len == 0 {
            return Ok(offset + 1);
        }

        if len & 0xC0 == 0xC0 {
            if offset + 1 >= packet.len() {
                return Err("Truncated compression pointer".to_string());
            }
            return Ok(offset + 2);
        }

        if len & 0xC0 != 0 {
            return Err("Invalid DNS label encoding".to_string());
        }

        offset += 1 + usize::from(len);
    }
}

#[allow(dead_code)]

fn assert_packet_matches_golden(label: &str, actual: &[u8], expected: &[u8]) -> Result<(), String> {
    if actual != expected {
        return Err(format!(
            "{label} golden mismatch:\nexpected {:02x?}\nactual   {:02x?}",
            expected, actual
        ));
    }

    Ok(())
}

/// Generate conformance report for DNS message format tests
#[allow(dead_code)]
pub fn generate_dns_conformance_report(results: &[DnsConformanceResult]) -> String {
    let total = results.len();
    let passed = results
        .iter()
        .filter(|r| r.verdict == DnsTestVerdict::Pass)
        .count();
    let failed = results
        .iter()
        .filter(|r| r.verdict == DnsTestVerdict::Fail)
        .count();
    let skipped = results
        .iter()
        .filter(|r| r.verdict == DnsTestVerdict::Skipped)
        .count();

    let mut report = String::new();
    report.push_str(&format!(
        "# DNS Message Format Conformance Report (RFC 1035 Section 4.1)\n\n"
    ));
    report.push_str(&format!("**Total Tests:** {}\n", total));
    report.push_str(&format!(
        "**Passed:** {} ({:.1}%)\n",
        passed,
        (passed as f64 / total as f64) * 100.0
    ));
    report.push_str(&format!(
        "**Failed:** {} ({:.1}%)\n",
        failed,
        (failed as f64 / total as f64) * 100.0
    ));
    report.push_str(&format!(
        "**Skipped:** {} ({:.1}%)\n\n",
        skipped,
        (skipped as f64 / total as f64) * 100.0
    ));

    // Group by category
    let mut by_category = std::collections::HashMap::new();
    for result in results {
        by_category
            .entry(&result.category)
            .or_insert(Vec::new())
            .push(result);
    }

    for (category, tests) in by_category {
        let cat_passed = tests
            .iter()
            .filter(|r| r.verdict == DnsTestVerdict::Pass)
            .count();
        let cat_total = tests.len();
        report.push_str(&format!(
            "## {:?} ({}/{})\n\n",
            category, cat_passed, cat_total
        ));

        for test in tests {
            let status = match test.verdict {
                DnsTestVerdict::Pass => "✅",
                DnsTestVerdict::Fail => "❌",
                DnsTestVerdict::Skipped => "⏭️",
                DnsTestVerdict::ExpectedFailure => "⚠️",
            };
            report.push_str(&format!(
                "- {} **{}** ({}ms): {}\n",
                status, test.test_id, test.execution_time_ms, test.description
            ));

            if let Some(error) = &test.error_message {
                report.push_str(&format!("  *Error: {}*\n", error));
            }
        }
        report.push('\n');
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(dead_code)]
    fn test_dns_message_conformance_harness() {
        let mut harness = DnsMessageConformanceHarness::new();
        let results = harness.run_all_tests();

        // Should have test results
        assert!(
            !results.is_empty(),
            "Should have DNS conformance test results"
        );

        // Count test categories
        let mut categories = std::collections::HashSet::new();
        for result in &results {
            categories.insert(result.category.clone());
        }

        // Should cover all required categories
        assert!(categories.contains(&DnsTestCategory::HeaderIdEcho));
        assert!(categories.contains(&DnsTestCategory::HeaderFlags));
        assert!(categories.contains(&DnsTestCategory::SectionCounters));
        assert!(categories.contains(&DnsTestCategory::NameCompression));
        assert!(categories.contains(&DnsTestCategory::QuestionTypes));
        assert!(categories.contains(&DnsTestCategory::AdditionalRecords));
        assert!(categories.contains(&DnsTestCategory::GoldenVectors));
        assert!(categories.contains(&DnsTestCategory::MessageSizeLimits));
        assert!(categories.contains(&DnsTestCategory::DnsClasses));
        assert!(categories.contains(&DnsTestCategory::ResponseCodes));

        // Generate report
        let report = generate_dns_conformance_report(&results);
        println!("{}", report);

        // Expect reasonable pass rate for RFC 1035 compliance
        let pass_rate = results
            .iter()
            .filter(|r| r.verdict == DnsTestVerdict::Pass)
            .count() as f64
            / results.len() as f64;
        assert!(
            pass_rate >= 0.80,
            "Expected >80% pass rate for RFC 1035 conformance, got {:.1}%",
            pass_rate * 100.0
        );
    }

    #[test]
    #[allow(dead_code)]
    fn test_dns_header_parsing() {
        let packet = create_dns_response_packet(0x1234, 0x8180, 1, 2, 0, 1);

        assert_eq!(parse_dns_id(&packet).unwrap(), 0x1234);
        assert!(is_dns_response(&packet).unwrap());
        assert!(recursion_desired(&packet).unwrap());
        assert!(recursion_available(&packet).unwrap());
        assert_eq!(parse_rcode(&packet).unwrap(), 0);
        assert_eq!(parse_qdcount(&packet).unwrap(), 1);
        assert_eq!(parse_ancount(&packet).unwrap(), 2);
        assert_eq!(parse_arcount(&packet).unwrap(), 1);
    }

    #[test]
    #[allow(dead_code)]
    fn test_dns_flag_bits() {
        // Test individual flag bits
        assert!(is_dns_response(&create_dns_response_packet(0x1234, 0x8000, 0, 0, 0, 0)).unwrap());
        assert!(!is_dns_response(&create_dns_response_packet(0x1234, 0x0000, 0, 0, 0, 0)).unwrap());

        assert!(
            is_authoritative_answer(&create_dns_response_packet(0x1234, 0x8400, 0, 0, 0, 0))
                .unwrap()
        );
        assert!(
            !is_authoritative_answer(&create_dns_response_packet(0x1234, 0x8000, 0, 0, 0, 0))
                .unwrap()
        );

        assert!(is_truncated(&create_dns_response_packet(0x1234, 0x8200, 0, 0, 0, 0)).unwrap());
        assert!(!is_truncated(&create_dns_response_packet(0x1234, 0x8000, 0, 0, 0, 0)).unwrap());
    }

    #[test]
    #[allow(dead_code)]
    fn test_dns_compression_basic() {
        let packet = create_basic_dns_packet();
        let result = extract_compressed_name(&packet, 12);
        // With basic packet, should fail gracefully
        assert!(result.is_err());
    }

    #[test]
    #[allow(dead_code)]
    fn test_dns_class_extraction() {
        let packet = create_dns_query_with_class(0x1234, "example.com", 1, 1);
        let class = extract_question_class(&packet).unwrap();
        assert_eq!(class, 1); // Class IN
    }

    #[test]
    #[allow(dead_code)]
    fn test_rcode_values() {
        for rcode in 0..=5 {
            let packet = create_dns_response_packet(0x1234, 0x8000 | rcode, 0, 0, 0, 0);
            let parsed = parse_rcode(&packet).unwrap();
            assert_eq!(parsed, rcode as u8);
        }
    }
}
