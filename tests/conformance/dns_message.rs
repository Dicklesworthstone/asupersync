#![allow(warnings)]
#![allow(clippy::all)]
//! DNS RFC 1035 Message Format Conformance Tests
//!
//! Validates RFC 1035 Section 4.1 message format compliance of the production
//! DNS code in `asupersync::net::dns`:
//! - Header ID echo on response
//! - QR/OPCODE/AA/TC/RD/RA/Z/RCODE bit positions and semantics
//! - QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT message section counters
//! - Domain name compression pointers, label and name length limits
//! - Question type encodings for A/AAAA/MX/TXT/CNAME/PTR queries
//! - EDNS0 OPT additional-record framing for replayable packet vectors
//! - UDP 512-byte limit triggers TC (truncated) flag
//! - DNS class values: IN (Internet), CH (Chaos), ANY (wildcard)
//! - Common RCODE values: NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED
//!
//! # What decides each verdict
//!
//! Test inputs are built locally by the `create_*` builders. Every verdict is
//! decided by a production outcome, never by a parser in this file:
//!
//! - `parse_dns_response_for_fuzz`: the resolver's response parser
//!   (`parse_dns_response` in src/net/dns/resolver.rs) accepting a message, or
//!   rejecting it with the asserted `DnsError` variant;
//! - `decode_dns_name_for_fuzz`: the resolver's name decoder returning a name
//!   and cursor, or rejecting the name;
//! - the public `Resolver` (`lookup_ip`, `lookup_mx`, `lookup_txt`) talking to
//!   a loopback nameserver run by this module. The queries production sends are
//!   captured byte for byte, and the scripted responses decide what production
//!   returns (records, `NoRecords`, `ServerError`, `Protocol`).
//!
//! Negative checks are paired with a positive control that differs in one
//! field, so a rejection is attributable to that field.
//!
//! A requirement that production cannot be driven to check (a field it never
//! reads or emits) is reported as `DnsTestVerdict::Skipped` with a note that
//! starts "production exposes no observable for this", so it is never counted
//! as a pass.
//!
//! # RFC 1035 Message Format (Section 4.1)
//!
//! ```text
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

use asupersync::net::dns::{
    DnsError, Resolver, ResolverConfig, decode_dns_name_for_fuzz, parse_dns_response_for_fuzz,
};
use asupersync::types::TaskId;
use asupersync::util::EntropySource;
use futures_lite::future::block_on;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
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

impl DnsMessageConformanceHarness {
    /// Create new DNS message format conformance harness
    pub fn new() -> Self {
        Self::default()
    }

    /// Run all DNS message format conformance tests
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
            self.skip_test(
                "HFL003",
                "AA (Authoritative Answer) bit correctly processed",
                DnsTestCategory::HeaderFlags,
                RequirementLevel::Must,
                "parse_dns_response reads only QR, TC and RCODE from the flags word \
                 (src/net/dns/resolver.rs:1296-1303) and the resolver never sets AA in \
                 its queries; HFL004 checks that AA is not misread as TC",
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
            self.skip_test(
                "HFL006",
                "RA (Recursion Available) bit correctly indicates server capability",
                DnsTestCategory::HeaderFlags,
                RequirementLevel::Must,
                "the resolver never reads RA (parse_dns_response reads only QR, TC and \
                 RCODE, src/net/dns/resolver.rs:1296-1303) and never sets it in queries; \
                 HFL008 checks that RA is not folded into RCODE",
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

    /// Test domain name compression and name limits (RFC 1035 Sections 2.3.4, 4.1.4)
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
            self.run_test(
                "CMP006",
                "Labels longer than 63 octets are rejected",
                DnsTestCategory::NameCompression,
                RequirementLevel::Must,
                || self.test_label_length_limit(),
            ),
            self.run_test(
                "CMP007",
                "Names longer than 255 octets are rejected, including through compression",
                DnsTestCategory::NameCompression,
                RequirementLevel::Must,
                || self.test_name_length_limit(),
            ),
        ]
    }

    /// Test DNS question types.
    fn test_question_types(&self) -> Vec<DnsConformanceResult> {
        vec![
            self.run_test(
                "QTP001",
                "Question type A encodes as 1",
                DnsTestCategory::QuestionTypes,
                RequirementLevel::Must,
                || self.test_question_type_encoding(TYPE_A, "A", run_ip_lookup),
            ),
            self.run_test(
                "QTP002",
                "Question type AAAA encodes as 28",
                DnsTestCategory::QuestionTypes,
                RequirementLevel::Must,
                || self.test_question_type_encoding(TYPE_AAAA, "AAAA", run_ip_lookup),
            ),
            self.run_test(
                "QTP003",
                "Question type MX encodes as 15",
                DnsTestCategory::QuestionTypes,
                RequirementLevel::Must,
                || self.test_question_type_encoding(TYPE_MX, "MX", run_mx_lookup),
            ),
            self.run_test(
                "QTP004",
                "Question type TXT encodes as 16",
                DnsTestCategory::QuestionTypes,
                RequirementLevel::Must,
                || self.test_question_type_encoding(TYPE_TXT, "TXT", run_txt_lookup),
            ),
            self.run_test(
                "QTP005",
                "Question type CNAME encodes as 5",
                DnsTestCategory::QuestionTypes,
                RequirementLevel::Must,
                || self.test_cname_type_recognized(),
            ),
            self.skip_test(
                "QTP006",
                "Question type PTR encodes as 12",
                DnsTestCategory::QuestionTypes,
                RequirementLevel::Must,
                "the resolver has no PTR lookup and DnsQueryType has no PTR member \
                 (src/net/dns/resolver.rs:795-829), so production never encodes or \
                 decodes type 12",
            ),
        ]
    }

    /// Test additional-record framing.
    fn test_additional_records(&self) -> Vec<DnsConformanceResult> {
        vec![
            self.skip_test(
                "ADR001",
                "EDNS0 OPT additional record encodes type 41 and payload size",
                DnsTestCategory::AdditionalRecords,
                RequirementLevel::Must,
                "the resolver never emits EDNS0 OPT (build_dns_query writes ARCOUNT=0, \
                 src/net/dns/resolver.rs:1012) and parse_dns_answer skips every \
                 non-IN-class record, OPT included, without surfacing its fields \
                 (resolver.rs:1145-1148); ADR002 and GLD003 check OPT framing",
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
    fn test_golden_vectors(&self) -> Vec<DnsConformanceResult> {
        vec![
            self.run_test(
                "GLD001",
                "A query golden vector remains stable for replay",
                DnsTestCategory::GoldenVectors,
                RequirementLevel::Must,
                || self.test_a_query_golden_vector(),
            ),
            self.skip_test(
                "GLD002",
                "PTR query golden vector remains stable for replay",
                DnsTestCategory::GoldenVectors,
                RequirementLevel::Must,
                "the resolver has no PTR lookup and DnsQueryType has no PTR member \
                 (src/net/dns/resolver.rs:795-829), so production never builds a PTR \
                 query to compare against a golden vector",
            ),
            self.run_test(
                "GLD003",
                "OPT additional-record golden vector remains stable for replay",
                DnsTestCategory::GoldenVectors,
                RequirementLevel::Must,
                || self.test_opt_record_golden_vector(),
            ),
            self.run_test(
                "GLD004",
                "A-record answer golden vector parses and resolves through production",
                DnsTestCategory::GoldenVectors,
                RequirementLevel::Must,
                || self.test_a_answer_golden_vector(),
            ),
            self.run_test(
                "GLD005",
                "CNAME chain golden vector parses and resolves through production",
                DnsTestCategory::GoldenVectors,
                RequirementLevel::Must,
                || self.test_cname_chain_golden_vector(),
            ),
            self.run_test(
                "GLD006",
                "Compressed-name MX golden vector parses and resolves through production",
                DnsTestCategory::GoldenVectors,
                RequirementLevel::Must,
                || self.test_compressed_mx_golden_vector(),
            ),
        ]
    }

    /// Test UDP message size limits (RFC 1035 Section 4.2.1)
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
            self.skip_test(
                "SIZ004",
                "Oversized message rejection",
                DnsTestCategory::MessageSizeLimits,
                RequirementLevel::Must,
                "production has no oversized-message rejection to drive: \
                 parse_dns_response accepts a message of any length and \
                 send_udp_dns_query reads into a fixed 2048-byte buffer without \
                 reporting truncation (src/net/dns/resolver.rs:1430)",
            ),
        ]
    }

    /// Test DNS class values (RFC 1035 Section 3.2.4)
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

    /// Record a requirement that production cannot be driven to check.
    ///
    /// The verdict is `Skipped`, never `Pass`, and the note says why.
    fn skip_test(
        &self,
        test_id: &str,
        description: &str,
        category: DnsTestCategory,
        requirement_level: RequirementLevel,
        reason: &str,
    ) -> DnsConformanceResult {
        DnsConformanceResult {
            test_id: test_id.to_string(),
            description: description.to_string(),
            category,
            requirement_level,
            verdict: DnsTestVerdict::Skipped,
            error_message: Some(format!("{SKIP_PREFIX}: {reason}")),
            execution_time_ms: 0,
        }
    }

    // =========================================================================
    // Header ID Echo Tests
    // =========================================================================

    /// HID001: the production parser accepts a response echoing the query ID,
    /// and the resolver sends the ID drawn from its entropy source and accepts
    /// the echo.
    fn test_id_echo_validation(&self) -> Result<(), String> {
        expect_parse_ok("ID 0x1234 echoed", &create_a_response(0x1234), 0x1234)?;

        let server = LoopbackNameserver::start(|query: &[u8], _transport: Transport| {
            Some(create_dns_response_to_query(
                query,
                FLAGS_RESPONSE,
                &[create_mx_record(QNAME_PTR, 10, "mail.example.com")],
            ))
        })?;
        let resolver = loopback_resolver(server.addr);
        let records = lookup_mx_records(&resolver, "example.com")
            .map_err(|err| format!("resolver rejected a response echoing its query ID: {err:?}"))?;
        expect_mx_records("echoed-ID lookup", &records, &[(10, "mail.example.com")])?;

        let queries = server.queries();
        let id = QUERY_ID.to_be_bytes();
        match queries.first() {
            Some(query) if query.bytes.get(..2) == Some(&id[..]) => Ok(()),
            other => Err(format!(
                "resolver query did not carry the entropy-drawn ID 0x{QUERY_ID:04x}: {other:02x?}"
            )),
        }
    }

    /// HID002: a response whose ID differs from the query's is rejected by the
    /// parser and by the resolver, even when it carries a usable answer.
    fn test_id_mismatch_rejection(&self) -> Result<(), String> {
        let response = create_a_response(0x5678);
        expect_parse_ok(
            "control: response checked against its own ID",
            &response,
            0x5678,
        )?;
        expect_parse_protocol_error("ID 0x5678 answering query 0x1234", &response, 0x1234)?;

        let server = LoopbackNameserver::start(|query: &[u8], _transport: Transport| {
            let mut response = create_dns_response_to_query(
                query,
                FLAGS_RESPONSE,
                &[create_mx_record(QNAME_PTR, 10, "mail.example.com")],
            );
            let spoofed = u16::from_be_bytes([response[0], response[1]]).wrapping_add(1);
            response[..2].copy_from_slice(&spoofed.to_be_bytes());
            Some(response)
        })?;
        let resolver = loopback_resolver(server.addr);
        match lookup_mx_records(&resolver, "example.com") {
            Err(DnsError::Protocol(_)) => Ok(()),
            other => Err(format!(
                "resolver must reject a response whose ID does not echo its query, got {other:?}"
            )),
        }
    }

    /// HID003: ID 0 is an ordinary 16-bit value to the parser.
    fn test_zero_id_handling(&self) -> Result<(), String> {
        let response = create_a_response(0x0000);
        expect_parse_ok("ID 0 answering query 0", &response, 0x0000)?;
        expect_parse_protocol_error("ID 0 answering query 0x1234", &response, 0x1234)
    }

    /// HID004: ID 0xFFFF is accepted, and both ID octets take part in the match.
    fn test_max_id_support(&self) -> Result<(), String> {
        let response = create_a_response(0xFFFF);
        expect_parse_ok("ID 0xFFFF answering query 0xFFFF", &response, 0xFFFF)?;
        expect_parse_protocol_error("ID 0xFFFF answering query 0x00FF", &response, 0x00FF)?;
        expect_parse_protocol_error("ID 0xFFFF answering query 0xFF00", &response, 0xFF00)
    }

    // =========================================================================
    // Header Flag Tests
    // =========================================================================

    /// HFL001: the parser accepts QR=1 and rejects the same message with QR=0.
    fn test_qr_bit_validation(&self) -> Result<(), String> {
        let response = create_a_response(QUERY_ID);
        expect_parse_ok("QR=1 response", &response, QUERY_ID)?;
        expect_parse_protocol_error(
            "same message with QR=0",
            &with_flags(response, FLAGS_RESPONSE & !FLAG_QR),
            QUERY_ID,
        )?;
        expect_parse_protocol_error(
            "a query packet",
            &create_dns_query_with_class(QUERY_ID, "example.com", TYPE_A, CLASS_IN),
            QUERY_ID,
        )
    }

    /// HFL002: the originator sets OPCODE; every query production originates
    /// carries OPCODE 0 (standard QUERY).
    ///
    /// Production never reads the OPCODE of a response
    /// (src/net/dns/resolver.rs:1296-1303), so the response side has no
    /// observable and is not asserted.
    fn test_opcode_field_parsing(&self) -> Result<(), String> {
        for query in capture_queries(run_every_lookup)? {
            let flags = header_flags(&query.bytes)?;
            if flags & MASK_OPCODE != 0 {
                return Err(format!(
                    "production query carries OPCODE {} instead of 0 (QUERY): {:02x?}",
                    (flags & MASK_OPCODE) >> 11,
                    query.bytes
                ));
            }
        }
        Ok(())
    }

    /// HFL004: the parser reads TC from bit 0x0200. With TC=1 it ignores an
    /// incomplete answer section; with TC=0, or with only AA set, the same
    /// message is rejected.
    fn test_tc_bit_indication(&self) -> Result<(), String> {
        // ANCOUNT claims five answers but none follow, as in a datagram cut
        // at the UDP size limit.
        let cut = create_dns_message(
            QUERY_ID,
            FLAGS_RESPONSE | FLAG_TC,
            [1, 5, 0, 0],
            &[question_section("example.com", TYPE_A, CLASS_IN)],
        );
        expect_parse_ok(
            "TC=1 response with an incomplete answer section",
            &cut,
            QUERY_ID,
        )?;
        expect_parse_protocol_error(
            "same message with TC=0",
            &with_flags(cut.clone(), FLAGS_RESPONSE),
            QUERY_ID,
        )?;
        expect_parse_protocol_error(
            "same message with AA=1 in place of TC=1",
            &with_flags(cut, FLAGS_RESPONSE | FLAG_AA),
            QUERY_ID,
        )
    }

    /// HFL005: every query production sends sets RD, and a response echoing RD
    /// is accepted.
    fn test_rd_bit_echo(&self) -> Result<(), String> {
        for query in capture_queries(run_every_lookup)? {
            if header_flags(&query.bytes)? & FLAG_RD == 0 {
                return Err(format!(
                    "production query does not set RD: {:02x?}",
                    query.bytes
                ));
            }
        }
        expect_parse_ok(
            "response echoing RD=1",
            &create_a_response(QUERY_ID),
            QUERY_ID,
        )
    }

    /// HFL007: every query production sends has the Z bits clear.
    fn test_z_bits_reserved(&self) -> Result<(), String> {
        for query in capture_queries(run_every_lookup)? {
            let flags = header_flags(&query.bytes)?;
            if flags & MASK_Z != 0 {
                return Err(format!(
                    "production query sets Z bits 0x{:04x}: {:02x?}",
                    flags & MASK_Z,
                    query.bytes
                ));
            }
        }
        Ok(())
    }

    /// HFL008: the resolver takes the response status from the low four bits
    /// only. RA, AD and CD (RFC 4035) sit next to RCODE and must not change
    /// the outcome.
    fn test_rcode_field_status(&self) -> Result<(), String> {
        let flags = FLAGS_RESPONSE | FLAGS_AD_CD;
        match lookup_mx_with_response_flags(flags, true)? {
            Ok(records) => expect_mx_records(
                "RCODE 0 with RA, AD and CD set",
                &records,
                &[(10, "mail.example.com")],
            )?,
            Err(err) => {
                return Err(format!(
                    "RCODE 0 with RA, AD and CD set: production lookup failed: {err:?}"
                ));
            }
        }
        match lookup_mx_with_response_flags(flags | RCODE_NXDOMAIN, false)? {
            Err(DnsError::NoRecords(_)) => {}
            other => {
                return Err(format!(
                    "RCODE 3 with RA, AD and CD set must report NoRecords, got {other:?}"
                ));
            }
        }
        match lookup_mx_with_response_flags(flags | RCODE_SERVFAIL, false)? {
            Err(DnsError::ServerError(_)) => Ok(()),
            other => Err(format!(
                "RCODE 2 with RA, AD and CD set must report ServerError, got {other:?}"
            )),
        }
    }

    // =========================================================================
    // Section Counter Tests
    // =========================================================================

    /// MSC001: the parser reads exactly QDCOUNT questions.
    fn test_qdcount_questions(&self) -> Result<(), String> {
        let q_a = question_section("example.com", TYPE_A, CLASS_IN);
        let q_aaaa = question_section("example.com", TYPE_AAAA, CLASS_IN);
        let message = |qdcount: u16, sections: &[Vec<u8>]| {
            create_dns_message(QUERY_ID, FLAGS_RESPONSE, [qdcount, 0, 0, 0], sections)
        };

        expect_parse_ok("QDCOUNT=0, no question", &message(0, &[]), QUERY_ID)?;
        expect_parse_ok(
            "QDCOUNT=1, one question",
            &message(1, &[q_a.clone()]),
            QUERY_ID,
        )?;
        expect_parse_ok(
            "QDCOUNT=2, two questions",
            &message(2, &[q_a.clone(), q_aaaa]),
            QUERY_ID,
        )?;
        expect_parse_protocol_error("QDCOUNT=2, one question", &message(2, &[q_a]), QUERY_ID)?;
        expect_parse_protocol_error("QDCOUNT=1, no question", &message(1, &[]), QUERY_ID)
    }

    /// MSC002: the parser reads exactly ANCOUNT answer records.
    fn test_ancount_answers(&self) -> Result<(), String> {
        let question = question_section("example.com", TYPE_A, CLASS_IN);
        let answer = |host: u8| create_a_record(QNAME_PTR, CLASS_IN, [192, 0, 2, host]);
        let one = [question.clone(), answer(1)];
        let three = [question, answer(1), answer(2), answer(3)];

        expect_parse_ok(
            "ANCOUNT=1, one answer",
            &create_dns_message(QUERY_ID, FLAGS_RESPONSE, [1, 1, 0, 0], &one),
            QUERY_ID,
        )?;
        expect_parse_ok(
            "ANCOUNT=3, three answers",
            &create_dns_message(QUERY_ID, FLAGS_RESPONSE, [1, 3, 0, 0], &three),
            QUERY_ID,
        )?;
        expect_parse_protocol_error(
            "ANCOUNT=2, one answer",
            &create_dns_message(QUERY_ID, FLAGS_RESPONSE, [1, 2, 0, 0], &one),
            QUERY_ID,
        )?;
        expect_parse_protocol_error(
            "ANCOUNT=4, three answers",
            &create_dns_message(QUERY_ID, FLAGS_RESPONSE, [1, 4, 0, 0], &three),
            QUERY_ID,
        )
    }

    /// MSC003: the parser reads exactly NSCOUNT authority records.
    fn test_nscount_authority(&self) -> Result<(), String> {
        let sections = [
            question_section("example.com", TYPE_A, CLASS_IN),
            create_resource_record(
                QNAME_PTR,
                TYPE_NS,
                CLASS_IN,
                TTL,
                &encoded_name("ns1.example.com"),
            ),
        ];

        expect_parse_ok(
            "NSCOUNT=1, one authority record",
            &create_dns_message(QUERY_ID, FLAGS_RESPONSE, [1, 0, 1, 0], &sections),
            QUERY_ID,
        )?;
        expect_parse_protocol_error(
            "NSCOUNT=2, one authority record",
            &create_dns_message(QUERY_ID, FLAGS_RESPONSE, [1, 0, 2, 0], &sections),
            QUERY_ID,
        )
    }

    /// MSC004: the parser reads exactly ARCOUNT additional records.
    fn test_arcount_additional(&self) -> Result<(), String> {
        let sections = [
            question_section("example.com", TYPE_A, CLASS_IN),
            create_a_record(&encoded_name("ns1.example.com"), CLASS_IN, [192, 0, 2, 53]),
        ];

        expect_parse_ok(
            "ARCOUNT=1, one additional record",
            &create_dns_message(QUERY_ID, FLAGS_RESPONSE, [1, 0, 0, 1], &sections),
            QUERY_ID,
        )?;
        expect_parse_protocol_error(
            "ARCOUNT=2, one additional record",
            &create_dns_message(QUERY_ID, FLAGS_RESPONSE, [1, 0, 0, 2], &sections),
            QUERY_ID,
        )
    }

    /// MSC005: counters far larger than the message are rejected, not trusted.
    fn test_section_counter_overflow(&self) -> Result<(), String> {
        expect_parse_protocol_error(
            "all four counters 0xFFFF, header only",
            &create_dns_response_packet(QUERY_ID, FLAGS_RESPONSE, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF),
            QUERY_ID,
        )?;

        let complete = create_a_response(QUERY_ID);
        expect_parse_ok("control: counters match the sections", &complete, QUERY_ID)?;
        expect_parse_protocol_error(
            "ANCOUNT 0xFFFF with one answer present",
            &with_counts(complete.clone(), [1, 0xFFFF, 0, 0]),
            QUERY_ID,
        )?;
        expect_parse_protocol_error(
            "ARCOUNT 0xFFFF with no additional record present",
            &with_counts(complete, [1, 1, 0, 0xFFFF]),
            QUERY_ID,
        )
    }

    // =========================================================================
    // Name Compression Tests
    // =========================================================================

    /// CMP001: a 2-octet pointer to the question name expands to that name and
    /// the cursor ends after the pointer.
    fn test_name_compression_expansion(&self) -> Result<(), String> {
        let packet = create_a_response(QUERY_ID);
        // The answer's owner name is the pointer C0 0C right after the question.
        let answer_offset = 12 + question_section("example.com", TYPE_A, CLASS_IN).len();

        expect_name(
            "owner name pointer to offset 12",
            &packet,
            answer_offset,
            "example.com",
            answer_offset + 2,
        )?;
        expect_parse_ok(
            "response whose answer owner is compressed",
            &packet,
            QUERY_ID,
        )
    }

    /// CMP002: pointer loops are rejected instead of followed.
    fn test_compression_loop_detection(&self) -> Result<(), String> {
        let mut self_loop = create_basic_dns_packet();
        self_loop.extend_from_slice(&[0xC0, 0x0C]);
        expect_name_protocol_error("pointer to itself", &self_loop, 12)?;

        // Offset 12 points to 14, and 14 points back to 12.
        let mut two_cycle = create_basic_dns_packet();
        two_cycle.extend_from_slice(&[0xC0, 0x0E, 0xC0, 0x0C]);
        expect_name_protocol_error("two-pointer cycle entered at 12", &two_cycle, 12)?;
        expect_name_protocol_error("two-pointer cycle entered at 14", &two_cycle, 14)?;

        let mut label_loop = create_basic_dns_packet();
        label_loop.extend_from_slice(&[3, b'a', b'b', b'c', 0xC0, 0x0C]);
        expect_name_protocol_error("label then pointer to its own start", &label_loop, 12)?;

        let looping_question = create_dns_message(
            QUERY_ID,
            FLAGS_RESPONSE,
            [1, 0, 0, 0],
            &[vec![0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]],
        );
        expect_parse_protocol_error(
            "response whose question name loops",
            &looping_question,
            QUERY_ID,
        )
    }

    /// CMP003: pointers that do not point to an earlier offset are rejected.
    fn test_forward_pointer_rejection(&self) -> Result<(), String> {
        let mut backward = create_basic_dns_packet();
        backward.extend_from_slice(&[0x00, 0xC0, 0x0C]);
        expect_name(
            "control: backward pointer to the root name",
            &backward,
            13,
            "",
            15,
        )?;

        let mut forward = create_basic_dns_packet();
        forward.extend_from_slice(&[0xC0, 0x0E, 0x00]);
        expect_name_protocol_error("pointer forward to offset 14", &forward, 12)?;

        let mut out_of_range = create_basic_dns_packet();
        out_of_range.extend_from_slice(&[0xC0, 0x20]);
        expect_name_protocol_error(
            "pointer to offset 32 beyond a 14-octet message",
            &out_of_range,
            12,
        )?;

        let mut truncated_pointer = create_basic_dns_packet();
        truncated_pointer.push(0xC0);
        expect_name_protocol_error("pointer missing its second octet", &truncated_pointer, 12)
    }

    /// CMP004: the reserved label types 10 and 01 are rejected.
    fn test_invalid_compression_format(&self) -> Result<(), String> {
        for (prefix, bits) in [(0x80u8, "10"), (0x40u8, "01")] {
            let mut packet = create_basic_dns_packet();
            packet.extend_from_slice(&[prefix, 0x00]);
            expect_name_protocol_error(&format!("reserved label type {bits}"), &packet, 12)?;
        }
        Ok(())
    }

    /// CMP005: labels and pointers chain across several levels, including a
    /// pointer to a name that itself ends in pointers.
    fn test_multilevel_compression(&self) -> Result<(), String> {
        let mut packet = create_basic_dns_packet();
        let com_offset = packet.len();
        packet.extend_from_slice(&[3, b'c', b'o', b'm', 0]);
        let example_offset = packet.len();
        packet.push(7);
        packet.extend_from_slice(b"example");
        packet.extend_from_slice(&pointer_to(com_offset));
        let www_offset = packet.len();
        packet.push(3);
        packet.extend_from_slice(b"www");
        packet.extend_from_slice(&pointer_to(example_offset));
        let pointer_only_offset = packet.len();
        packet.extend_from_slice(&pointer_to(www_offset));

        expect_name(
            "label chain through two pointers",
            &packet,
            www_offset,
            "www.example.com",
            pointer_only_offset,
        )?;
        expect_name(
            "pointer to a name that itself ends in pointers",
            &packet,
            pointer_only_offset,
            "www.example.com",
            pointer_only_offset + 2,
        )
    }

    /// CMP006: a 63-octet label is accepted and a 64-octet label is rejected,
    /// by the name decoder and by the whole-message parser.
    fn test_label_length_limit(&self) -> Result<(), String> {
        let mut max_label = create_basic_dns_packet();
        max_label.extend_from_slice(&single_label_name(63));
        expect_name(
            "63-octet label",
            &max_label,
            12,
            &"a".repeat(63),
            12 + 1 + 63 + 1,
        )?;

        let mut long_label = create_basic_dns_packet();
        long_label.extend_from_slice(&single_label_name(64));
        expect_name_protocol_error("64-octet label", &long_label, 12)?;

        let response = |label_len: usize| {
            let mut question = single_label_name(label_len);
            question.extend_from_slice(&TYPE_A.to_be_bytes());
            question.extend_from_slice(&CLASS_IN.to_be_bytes());
            create_dns_message(QUERY_ID, FLAGS_RESPONSE, [1, 0, 0, 0], &[question])
        };
        expect_parse_ok("question with a 63-octet label", &response(63), QUERY_ID)?;
        expect_parse_protocol_error("question with a 64-octet label", &response(64), QUERY_ID)
    }

    /// CMP007: a 255-octet name is accepted, a 256-octet name is rejected, and
    /// compression cannot expand a name past the limit.
    fn test_name_length_limit(&self) -> Result<(), String> {
        let longest = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        let too_long = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );

        let mut packet = create_basic_dns_packet();
        encode_domain_name(&longest, &mut packet);
        let wire_len = packet.len() - 12;
        if wire_len != 255 {
            return Err(format!(
                "test input error: the longest name encodes to {wire_len} octets, not 255"
            ));
        }
        expect_name("255-octet name", &packet, 12, &longest, packet.len())?;

        let mut over = create_basic_dns_packet();
        encode_domain_name(&too_long, &mut over);
        expect_name_protocol_error("256-octet name", &over, 12)?;

        let pointer_offset = packet.len();
        packet.extend_from_slice(&pointer_to(12));
        let prefixed_offset = packet.len();
        packet.push(3);
        packet.extend_from_slice(b"www");
        packet.extend_from_slice(&pointer_to(12));
        expect_name(
            "pointer to the 255-octet name",
            &packet,
            pointer_offset,
            &longest,
            prefixed_offset,
        )?;
        expect_name_protocol_error(
            "label plus pointer expanding to 259 octets",
            &packet,
            prefixed_offset,
        )
    }

    // =========================================================================
    // Question Type Tests
    // =========================================================================

    /// QTP001-QTP004: the query production sends for `qtype` is byte-identical
    /// to the RFC 1035 encoding with that QTYPE value.
    fn test_question_type_encoding(
        &self,
        qtype: u16,
        display_name: &str,
        run: fn(&Resolver),
    ) -> Result<(), String> {
        let queries = capture_queries(run)?;
        let expected = create_expected_resolver_query(QUERY_ID, "example.com", qtype);
        if queries.iter().any(|query| query.bytes == expected) {
            Ok(())
        } else {
            Err(format!(
                "{display_name}: no production query matched the encoding with QTYPE {qtype}\n\
                 expected {expected:02x?}\ncaptured {queries:02x?}"
            ))
        }
    }

    /// QTP005: production has no CNAME query API, so this checks the closest
    /// observable: an answer record of type 5 is decoded as a CNAME and the
    /// resolver follows it to the target name.
    fn test_cname_type_recognized(&self) -> Result<(), String> {
        let alias_query = create_expected_resolver_query(QUERY_ID, "alias.example.com", TYPE_MX);
        let target_query = create_expected_resolver_query(QUERY_ID, "target.example.com", TYPE_MX);
        let server = {
            let alias_query = alias_query.clone();
            let target_query = target_query.clone();
            LoopbackNameserver::start(move |query: &[u8], _transport: Transport| {
                let answers = if query == alias_query.as_slice() {
                    vec![create_resource_record(
                        QNAME_PTR,
                        TYPE_CNAME,
                        CLASS_IN,
                        TTL,
                        &encoded_name("target.example.com"),
                    )]
                } else if query == target_query.as_slice() {
                    vec![create_mx_record(QNAME_PTR, 10, "mail.example.com")]
                } else {
                    return Some(create_dns_response_to_query(
                        query,
                        FLAGS_RESPONSE | RCODE_REFUSED,
                        &[],
                    ));
                };
                Some(create_dns_response_to_query(
                    query,
                    FLAGS_RESPONSE,
                    &answers,
                ))
            })?
        };
        let resolver = loopback_resolver(server.addr);
        let records = lookup_mx_records(&resolver, "alias.example.com")
            .map_err(|err| format!("production did not follow a type-5 (CNAME) answer: {err:?}"))?;
        expect_mx_records("MX through a CNAME", &records, &[(10, "mail.example.com")])?;

        if server
            .queries()
            .iter()
            .any(|query| query.bytes == target_query)
        {
            Ok(())
        } else {
            Err("production never queried the CNAME target".to_string())
        }
    }

    // =========================================================================
    // Additional Record Tests
    // =========================================================================

    /// ADR002: the parser reads exactly ARCOUNT additional records, OPT
    /// included, and bounds the OPT RDATA by RDLENGTH.
    fn test_edns0_opt_record_count(&self) -> Result<(), String> {
        let with_opt = with_flags(
            create_dns_query_with_additional(
                QUERY_ID,
                "example.com",
                TYPE_AAAA,
                CLASS_IN,
                &create_opt_record(1232, 0, 0, 0, &[]),
            ),
            FLAGS_RESPONSE,
        );
        expect_parse_ok("ARCOUNT=1 with one OPT record", &with_opt, QUERY_ID)?;
        expect_parse_protocol_error(
            "ARCOUNT=2 with one OPT record",
            &with_counts(with_opt, [1, 0, 0, 2]),
            QUERY_ID,
        )?;

        // RDLENGTH sits after the root owner name (1), TYPE (2), CLASS (2) and TTL (4).
        let mut overrun_opt = create_opt_record(4096, 0, 0, 0x8000, &[0xde, 0xad, 0xbe, 0xef]);
        overrun_opt[9..11].copy_from_slice(&8u16.to_be_bytes());
        let overrun = with_flags(
            create_dns_query_with_additional(
                QUERY_ID,
                "example.com",
                TYPE_A,
                CLASS_IN,
                &overrun_opt,
            ),
            FLAGS_RESPONSE,
        );
        expect_parse_protocol_error(
            "OPT record whose RDLENGTH overruns the message",
            &overrun,
            QUERY_ID,
        )
    }

    // =========================================================================
    // Golden Vector Tests
    // =========================================================================

    /// GLD001: the A query production sends is byte-identical to the golden.
    fn test_a_query_golden_vector(&self) -> Result<(), String> {
        let queries = capture_queries(run_ip_lookup)?;
        if queries.iter().any(|query| query.bytes == GOLDEN_A_QUERY) {
            Ok(())
        } else {
            Err(format!(
                "no production query matched the A-query golden vector\n\
                 expected {GOLDEN_A_QUERY:02x?}\ncaptured {queries:02x?}"
            ))
        }
    }

    /// GLD003: a response carrying the EDNS0 OPT golden record parses.
    fn test_opt_record_golden_vector(&self) -> Result<(), String> {
        expect_parse_ok(
            "OPT additional-record golden",
            GOLDEN_OPT_RESPONSE,
            QUERY_ID,
        )
    }

    /// GLD004: the A-answer golden parses, and replayed to the resolver it
    /// resolves to 192.0.2.1.
    fn test_a_answer_golden_vector(&self) -> Result<(), String> {
        expect_parse_ok("A-answer golden", GOLDEN_A_RESPONSE, QUERY_ID)?;
        let server = start_golden_nameserver()?;
        let resolver = loopback_resolver(server.addr);
        let addresses = lookup_ip_addrs(&resolver, "example.com")
            .map_err(|err| format!("A-answer golden replay failed in production: {err:?}"))?;
        expect_addresses("A-answer golden replay", &addresses, &[[192, 0, 2, 1]])
    }

    /// GLD005: the CNAME-chain golden parses, and replayed to the resolver
    /// www.example.com resolves through the alias to 192.0.2.1.
    fn test_cname_chain_golden_vector(&self) -> Result<(), String> {
        expect_parse_ok("CNAME-chain golden", GOLDEN_CNAME_CHAIN_RESPONSE, QUERY_ID)?;
        let server = start_golden_nameserver()?;
        let resolver = loopback_resolver(server.addr);
        let addresses = lookup_ip_addrs(&resolver, "www.example.com")
            .map_err(|err| format!("CNAME-chain golden replay failed in production: {err:?}"))?;
        expect_addresses("CNAME-chain golden replay", &addresses, &[[192, 0, 2, 1]])?;

        if server
            .queries()
            .iter()
            .any(|query| query.bytes == GOLDEN_A_QUERY)
        {
            Ok(())
        } else {
            Err("production resolved the CNAME chain without querying the alias target".into())
        }
    }

    /// GLD006: the compressed-name MX golden parses, and replayed to the
    /// resolver both exchanges expand through their pointer chains.
    fn test_compressed_mx_golden_vector(&self) -> Result<(), String> {
        expect_parse_ok(
            "compressed-name MX golden",
            GOLDEN_COMPRESSED_MX_RESPONSE,
            QUERY_ID,
        )?;
        let server = start_golden_nameserver()?;
        let resolver = loopback_resolver(server.addr);
        let records = lookup_mx_records(&resolver, "example.com")
            .map_err(|err| format!("compressed MX golden replay failed in production: {err:?}"))?;
        expect_mx_records(
            "compressed MX golden replay",
            &records,
            &[(10, "mail.example.com"), (20, "backup.mail.example.com")],
        )
    }

    // =========================================================================
    // Message Size Limit Tests
    // =========================================================================

    /// SIZ001: an answer over 512 octets arrives over UDP cut at 512 octets
    /// with TC=1. Production must discard it, retry over TCP and use the
    /// complete answer.
    fn test_udp_512_limit_tc_flag(&self) -> Result<(), String> {
        let octets: Vec<[u8; 4]> = (1..=40u8).map(|host| [192, 0, 2, host]).collect();
        let answers: Vec<Vec<u8>> = octets
            .iter()
            .map(|address| create_a_record(QNAME_PTR, CLASS_IN, *address))
            .collect();
        let full = create_dns_response_to_query(GOLDEN_A_QUERY, FLAGS_RESPONSE, &answers);
        if full.len() <= 512 {
            return Err(format!(
                "test input error: the full response is only {} octets",
                full.len()
            ));
        }
        let mut truncated = with_flags(full.clone(), FLAGS_RESPONSE | FLAG_TC);
        truncated.truncate(512);

        let server = LoopbackNameserver::start(move |query: &[u8], transport: Transport| {
            if query != GOLDEN_A_QUERY {
                return Some(create_dns_response_to_query(query, FLAGS_RESPONSE, &[]));
            }
            Some(match transport {
                Transport::Udp => truncated.clone(),
                Transport::Tcp => full.clone(),
            })
        })?;
        let resolver = loopback_resolver(server.addr);
        let addresses = lookup_ip_addrs(&resolver, "example.com")
            .map_err(|err| format!("production failed on a TC=1 UDP answer: {err:?}"))?;
        expect_addresses("TC=1 UDP answer completed over TCP", &addresses, &octets)?;

        let retried_over_tcp = server
            .queries()
            .iter()
            .any(|query| query.transport == Transport::Tcp && query.bytes == GOLDEN_A_QUERY);
        if retried_over_tcp {
            Ok(())
        } else {
            Err("production never retried the truncated A query over TCP".to_string())
        }
    }

    /// SIZ002: an answer within 512 octets with TC=0 is used as received over
    /// UDP, with no TCP retry.
    fn test_within_512_no_tc(&self) -> Result<(), String> {
        if GOLDEN_A_RESPONSE.len() > 512 {
            return Err("test input error: the A-answer golden exceeds 512 octets".to_string());
        }
        let server = start_golden_nameserver()?;
        let resolver = loopback_resolver(server.addr);
        let addresses = lookup_ip_addrs(&resolver, "example.com")
            .map_err(|err| format!("production failed on a TC=0 UDP answer: {err:?}"))?;
        expect_addresses("TC=0 UDP answer", &addresses, &[[192, 0, 2, 1]])?;

        let tcp_queries = server
            .queries()
            .iter()
            .filter(|query| query.transport == Transport::Tcp)
            .count();
        if tcp_queries == 0 {
            Ok(())
        } else {
            Err(format!(
                "production retried over TCP {tcp_queries} time(s) without TC set"
            ))
        }
    }

    /// SIZ003: a 12-octet header-only response parses; anything shorter than
    /// a header is rejected.
    fn test_minimum_message_size(&self) -> Result<(), String> {
        let minimal = create_basic_dns_packet();
        expect_parse_ok("12-octet header-only response", &minimal, 0x1234)?;
        expect_parse_protocol_error("11-octet message", &minimal[..11], 0x1234)?;
        expect_parse_protocol_error("empty message", &[], 0x1234)
    }

    // =========================================================================
    // DNS Class Tests
    // =========================================================================

    /// CLS001: every query production sends carries QCLASS IN, and an
    /// IN-class answer is used.
    fn test_class_in_processing(&self) -> Result<(), String> {
        let server = start_golden_nameserver()?;
        let resolver = loopback_resolver(server.addr);
        let addresses = lookup_ip_addrs(&resolver, "example.com")
            .map_err(|err| format!("IN-class answer rejected by production: {err:?}"))?;
        expect_addresses("IN-class answer", &addresses, &[[192, 0, 2, 1]])?;

        for query in &server.queries() {
            if !query.bytes.ends_with(&CLASS_IN.to_be_bytes()) {
                return Err(format!(
                    "production query does not end in QCLASS IN: {:02x?}",
                    query.bytes
                ));
            }
        }
        Ok(())
    }

    /// CLS002: a CH-class record is framed by its RDLENGTH and not used as
    /// Internet data, and the IN-class record after it still resolves.
    fn test_class_ch_processing(&self) -> Result<(), String> {
        let answers = vec![
            create_a_record(QNAME_PTR, CLASS_CH, [192, 0, 2, 66]),
            create_a_record(QNAME_PTR, CLASS_IN, [192, 0, 2, 1]),
        ];
        match lookup_ip_with_a_answers(answers)? {
            Ok(addresses) => expect_addresses(
                "CH-class record followed by an IN-class record",
                &addresses,
                &[[192, 0, 2, 1]],
            ),
            Err(err) => Err(format!(
                "CH-class record broke production resolution: {err:?}"
            )),
        }
    }

    /// CLS003: a response echoing a QCLASS=ANY question parses, and an answer
    /// record of class ANY (valid only as a QCLASS) is not used as data.
    fn test_class_any_processing(&self) -> Result<(), String> {
        expect_parse_ok(
            "response to a QCLASS=ANY question",
            &create_dns_message(
                QUERY_ID,
                FLAGS_RESPONSE,
                [1, 0, 0, 0],
                &[question_section("example.com", TYPE_A, CLASS_ANY)],
            ),
            QUERY_ID,
        )?;

        let answers = vec![
            create_a_record(QNAME_PTR, CLASS_ANY, [192, 0, 2, 99]),
            create_a_record(QNAME_PTR, CLASS_IN, [192, 0, 2, 1]),
        ];
        match lookup_ip_with_a_answers(answers)? {
            Ok(addresses) => expect_addresses(
                "ANY-class record followed by an IN-class record",
                &addresses,
                &[[192, 0, 2, 1]],
            ),
            Err(err) => Err(format!(
                "ANY-class record broke production resolution: {err:?}"
            )),
        }
    }

    /// CLS004: a record of reserved class 0 is not used; with nothing else
    /// in the answer, production reports NoRecords.
    fn test_invalid_class_rejection(&self) -> Result<(), String> {
        let answers = vec![create_a_record(QNAME_PTR, 0, [192, 0, 2, 98])];
        match lookup_ip_with_a_answers(answers)? {
            Err(DnsError::NoRecords(_)) => Ok(()),
            other => Err(format!(
                "a class-0 record must not resolve; production returned {other:?}"
            )),
        }
    }

    // =========================================================================
    // Response Code Tests
    // =========================================================================

    /// RCD001: NOERROR with an answer yields the records.
    fn test_rcode_noerror(&self) -> Result<(), String> {
        match lookup_mx_with_response_flags(FLAGS_RESPONSE, true)? {
            Ok(records) => expect_mx_records("NOERROR", &records, &[(10, "mail.example.com")]),
            Err(err) => Err(format!(
                "RCODE 0 (NOERROR) with an MX answer failed in production: {err:?}"
            )),
        }
    }

    /// RCD002: FORMERR surfaces as a server error.
    fn test_rcode_formerr(&self) -> Result<(), String> {
        expect_rcode_server_error(RCODE_FORMERR, "FORMERR")
    }

    /// RCD003: SERVFAIL surfaces as a server error.
    fn test_rcode_servfail(&self) -> Result<(), String> {
        expect_rcode_server_error(RCODE_SERVFAIL, "SERVFAIL")
    }

    /// RCD004: NXDOMAIN surfaces as "no such name", not as a server error.
    fn test_rcode_nxdomain(&self) -> Result<(), String> {
        match lookup_mx_with_response_flags(FLAGS_RESPONSE | RCODE_NXDOMAIN, false)? {
            Err(DnsError::NoRecords(_)) => Ok(()),
            other => Err(format!(
                "RCODE 3 (NXDOMAIN) must surface as DnsError::NoRecords, got {other:?}"
            )),
        }
    }

    /// RCD005: NOTIMP surfaces as a server error.
    fn test_rcode_notimp(&self) -> Result<(), String> {
        expect_rcode_server_error(RCODE_NOTIMP, "NOTIMP")
    }

    /// RCD006: REFUSED surfaces as a server error.
    fn test_rcode_refused(&self) -> Result<(), String> {
        expect_rcode_server_error(RCODE_REFUSED, "REFUSED")
    }

    /// RCD007: the reserved RCODE values 6-15 are never taken as success or
    /// as NXDOMAIN.
    fn test_reserved_rcode_values(&self) -> Result<(), String> {
        for rcode in 6..=15u16 {
            expect_rcode_server_error(rcode, "reserved")?;
        }
        Ok(())
    }
}

// =============================================================================
// Constants and Golden Vectors
// =============================================================================

const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;
const TYPE_MX: u16 = 15;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;
const TYPE_OPT: u16 = 41;
const CLASS_IN: u16 = 1;
const CLASS_CH: u16 = 3;
const CLASS_ANY: u16 = 255;

const RCODE_FORMERR: u16 = 1;
const RCODE_SERVFAIL: u16 = 2;
const RCODE_NXDOMAIN: u16 = 3;
const RCODE_NOTIMP: u16 = 4;
const RCODE_REFUSED: u16 = 5;

const FLAG_QR: u16 = 0x8000;
const FLAG_AA: u16 = 0x0400;
const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;
const MASK_OPCODE: u16 = 0x7800;
const MASK_Z: u16 = 0x0070;
/// AD and CD (RFC 4035), carved out of RFC 1035's Z field.
const FLAGS_AD_CD: u16 = 0x0030;
/// QR=1, RD=1, RA=1, RCODE=0: an ordinary recursive response.
const FLAGS_RESPONSE: u16 = 0x8180;

/// Query ID the loopback resolver draws from its entropy source.
const QUERY_ID: u16 = 0x1234;
const TTL: u32 = 3600;
/// Compression pointer to the question name at offset 12.
const QNAME_PTR: &[u8] = &[0xC0, 0x0C];
/// Budget for one production lookup against the loopback nameserver. Every
/// scenario answers, so this only matters on a stalled machine.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);
/// Every skipped requirement's note starts with this.
const SKIP_PREFIX: &str = "production exposes no observable for this";

/// The A query for example.com that production sends with ID 0x1234
/// (RD=1, QDCOUNT=1, QTYPE A, QCLASS IN).
const GOLDEN_A_QUERY: &[u8] = &[
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // header
    0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, // name
    0x00, 0x01, 0x00, 0x01, // QTYPE A, QCLASS IN
];

/// example.com A 192.0.2.1, owner name compressed to the question name.
const GOLDEN_A_RESPONSE: &[u8] = &[
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // header
    0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, // @12
    0x00, 0x01, 0x00, 0x01, // QTYPE A, QCLASS IN
    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, // @29 A IN
    0xc0, 0x00, 0x02, 0x01, // 192.0.2.1
];

/// www.example.com CNAME example.com, followed by example.com A 192.0.2.1.
/// Both names point into the question name ("example" label at offset 16).
const GOLDEN_CNAME_CHAIN_RESPONSE: &[u8] = &[
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // header
    0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
    0x00, // @12 www.example.com
    0x00, 0x01, 0x00, 0x01, // QTYPE A, QCLASS IN
    0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x02, // @33 CNAME
    0xc0, 0x10, // -> example.com
    0xc0, 0x10, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04, // @47 A IN
    0xc0, 0x00, 0x02, 0x01, // 192.0.2.1
];

/// example.com MX 10 mail.example.com and MX 20 backup.mail.example.com.
/// The first exchange points to the question name; the second points to the
/// first exchange, which points on to the question name.
const GOLDEN_COMPRESSED_MX_RESPONSE: &[u8] = &[
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // header
    0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, // @12
    0x00, 0x0f, 0x00, 0x01, // QTYPE MX, QCLASS IN
    0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x09, // @29 MX IN
    0x00, 0x0a, 0x04, b'm', b'a', b'i', b'l', 0xc0, 0x0c, // 10 mail(@43).example.com
    0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x0b, // @50 MX IN
    0x00, 0x14, 0x06, b'b', b'a', b'c', b'k', b'u', b'p', 0xc0, 0x2b, // 20 backup.@43
];

/// Response to the A query for example.com carrying one EDNS0 OPT record
/// (UDP payload 4096, DO bit, 4 octets of option data) in the additional
/// section.
const GOLDEN_OPT_RESPONSE: &[u8] = &[
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // header
    0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, // @12
    0x00, 0x01, 0x00, 0x01, // QTYPE A, QCLASS IN
    0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x04, // OPT
    0xde, 0xad, 0xbe, 0xef, // option data
];

// =============================================================================
// Packet Builders (test inputs only; parsing is always production)
// =============================================================================

/// Create a basic DNS response packet
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
fn create_basic_dns_packet() -> Vec<u8> {
    create_dns_response_packet(0x1234, 0x8000, 0, 0, 0, 0)
}

/// Create DNS query packet with specific class
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

/// A header followed by `sections`, concatenated as given.
fn create_dns_message(id: u16, flags: u16, counts: [u16; 4], sections: &[Vec<u8>]) -> Vec<u8> {
    let mut message =
        create_dns_response_packet(id, flags, counts[0], counts[1], counts[2], counts[3]);
    for section in sections {
        message.extend_from_slice(section);
    }
    message
}

/// The example.com A response (192.0.2.1, owner compressed) with `id`.
fn create_a_response(id: u16) -> Vec<u8> {
    create_dns_message(
        id,
        FLAGS_RESPONSE,
        [1, 1, 0, 0],
        &[
            question_section("example.com", TYPE_A, CLASS_IN),
            create_a_record(QNAME_PTR, CLASS_IN, [192, 0, 2, 1]),
        ],
    )
}

/// The query an RFC 1035 stub resolver sends: only RD set (QR=0, OPCODE=0,
/// Z=0, RCODE=0), QDCOUNT=1, one IN-class question and no other sections.
fn create_expected_resolver_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    create_dns_message(
        id,
        FLAG_RD,
        [1, 0, 0, 0],
        &[question_section(name, qtype, CLASS_IN)],
    )
}

/// A response to a production query (one question, nothing after it) that
/// echoes the ID and the question, sets `flags` and carries `answers`.
fn create_dns_response_to_query(query: &[u8], flags: u16, answers: &[Vec<u8>]) -> Vec<u8> {
    let id = query
        .get(..2)
        .map_or(0, |bytes| u16::from_be_bytes([bytes[0], bytes[1]]));
    let question = query.get(12..).unwrap_or(&[]);
    let mut response = create_dns_response_packet(
        id,
        flags,
        u16::from(!question.is_empty()),
        answers.len() as u16,
        0,
        0,
    );
    response.extend_from_slice(question);
    for answer in answers {
        response.extend_from_slice(answer);
    }
    response
}

/// One question entry: QNAME, QTYPE, QCLASS.
fn question_section(name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
    let mut question = encoded_name(name);
    question.extend_from_slice(&qtype.to_be_bytes());
    question.extend_from_slice(&qclass.to_be_bytes());
    question
}

/// `name` in uncompressed wire format.
fn encoded_name(name: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    encode_domain_name(name, &mut encoded);
    encoded
}

/// A name of one label of `len` octets, written raw so lengths above 63 can
/// be expressed.
fn single_label_name(len: usize) -> Vec<u8> {
    let mut name = vec![len as u8];
    name.extend_from_slice(&vec![b'a'; len]);
    name.push(0);
    name
}

/// A compression pointer to `offset`.
fn pointer_to(offset: usize) -> [u8; 2] {
    (0xC000u16 | offset as u16).to_be_bytes()
}

/// One resource record (RFC 1035 Section 4.1.3) with an already-encoded owner.
fn create_resource_record(
    owner: &[u8],
    rr_type: u16,
    rr_class: u16,
    ttl: u32,
    rdata: &[u8],
) -> Vec<u8> {
    let mut record = owner.to_vec();
    record.extend_from_slice(&rr_type.to_be_bytes());
    record.extend_from_slice(&rr_class.to_be_bytes());
    record.extend_from_slice(&ttl.to_be_bytes());
    record.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    record.extend_from_slice(rdata);
    record
}

/// An A record of class `rr_class`.
fn create_a_record(owner: &[u8], rr_class: u16, address: [u8; 4]) -> Vec<u8> {
    create_resource_record(owner, TYPE_A, rr_class, TTL, &address)
}

/// An IN-class MX record with an uncompressed exchange name.
fn create_mx_record(owner: &[u8], preference: u16, exchange: &str) -> Vec<u8> {
    let mut rdata = preference.to_be_bytes().to_vec();
    encode_domain_name(exchange, &mut rdata);
    create_resource_record(owner, TYPE_MX, CLASS_IN, TTL, &rdata)
}

/// `packet` with its flags word replaced.
fn with_flags(mut packet: Vec<u8>, flags: u16) -> Vec<u8> {
    if packet.len() >= 4 {
        packet[2..4].copy_from_slice(&flags.to_be_bytes());
    }
    packet
}

/// `packet` with QDCOUNT, ANCOUNT, NSCOUNT and ARCOUNT replaced.
fn with_counts(mut packet: Vec<u8>, counts: [u16; 4]) -> Vec<u8> {
    for (index, count) in counts.iter().enumerate() {
        let at = 4 + index * 2;
        if packet.len() >= at + 2 {
            packet[at..at + 2].copy_from_slice(&count.to_be_bytes());
        }
    }
    packet
}

// =============================================================================
// Production Outcome Checks
// =============================================================================

/// Production's response parser must accept `packet`.
fn expect_parse_ok(label: &str, packet: &[u8], expected_id: u16) -> Result<(), String> {
    parse_dns_response_for_fuzz(packet, expected_id).map_err(|err| {
        format!("{label}: production parse_dns_response rejected a well-formed message: {err:?}")
    })
}

/// Production's response parser must reject `packet` with `DnsError::Protocol`.
fn expect_parse_protocol_error(label: &str, packet: &[u8], expected_id: u16) -> Result<(), String> {
    match parse_dns_response_for_fuzz(packet, expected_id) {
        Err(DnsError::Protocol(_)) => Ok(()),
        Err(other) => Err(format!(
            "{label}: expected DnsError::Protocol from production parse_dns_response, got {other:?}"
        )),
        Ok(()) => Err(format!(
            "{label}: production parse_dns_response accepted a message it must reject"
        )),
    }
}

/// Production's name decoder must return `expected_name` with the cursor at
/// `expected_end`.
fn expect_name(
    label: &str,
    packet: &[u8],
    start: usize,
    expected_name: &str,
    expected_end: usize,
) -> Result<(), String> {
    let mut offset = start;
    match decode_dns_name_for_fuzz(packet, &mut offset) {
        Ok(name) if name == expected_name && offset == expected_end => Ok(()),
        Ok(name) => Err(format!(
            "{label}: production decoded {name:?} with cursor {offset}, \
             expected {expected_name:?} with cursor {expected_end}"
        )),
        Err(err) => Err(format!(
            "{label}: production decode_dns_name rejected a valid name: {err:?}"
        )),
    }
}

/// Production's name decoder must reject the name at `start` with
/// `DnsError::Protocol`.
fn expect_name_protocol_error(label: &str, packet: &[u8], start: usize) -> Result<(), String> {
    let mut offset = start;
    match decode_dns_name_for_fuzz(packet, &mut offset) {
        Err(DnsError::Protocol(_)) => Ok(()),
        Err(other) => Err(format!(
            "{label}: expected DnsError::Protocol from production decode_dns_name, got {other:?}"
        )),
        Ok(name) => Err(format!(
            "{label}: production decode_dns_name accepted {name:?}; it must reject this name"
        )),
    }
}

/// Production's MX lookup must have returned exactly `expected`, in order.
fn expect_mx_records(
    label: &str,
    actual: &[(u16, String)],
    expected: &[(u16, &str)],
) -> Result<(), String> {
    let matches = actual.len() == expected.len()
        && actual
            .iter()
            .zip(expected)
            .all(|(got, want)| got.0 == want.0 && got.1.as_str() == want.1);
    if matches {
        Ok(())
    } else {
        Err(format!(
            "{label}: production returned MX records {actual:?}, expected {expected:?}"
        ))
    }
}

/// Production's IP lookup must have returned exactly `expected`, in order.
fn expect_addresses(label: &str, actual: &[IpAddr], expected: &[[u8; 4]]) -> Result<(), String> {
    let expected: Vec<IpAddr> = expected
        .iter()
        .map(|octets| IpAddr::V4(Ipv4Addr::from(*octets)))
        .collect();
    if actual == expected.as_slice() {
        Ok(())
    } else {
        Err(format!(
            "{label}: production resolved {actual:?}, expected {expected:?}"
        ))
    }
}

/// The flags word of a message production emitted.
fn header_flags(message: &[u8]) -> Result<u16, String> {
    message
        .get(2..4)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
        .ok_or_else(|| {
            format!("production emitted a message shorter than a header: {message:02x?}")
        })
}

// =============================================================================
// Loopback Nameserver Driving the Production Resolver
// =============================================================================

/// Transport a query reached the loopback nameserver on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    Udp,
    Tcp,
}

/// One query production sent to the loopback nameserver, byte for byte.
#[derive(Debug, Clone)]
struct CapturedQuery {
    transport: Transport,
    bytes: Vec<u8>,
}

/// A loopback nameserver serving UDP and TCP on one port. The test scripts
/// its responses, and it records every query production sends to it.
struct LoopbackNameserver {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    queries: Arc<Mutex<Vec<CapturedQuery>>>,
    threads: Vec<JoinHandle<()>>,
}

impl LoopbackNameserver {
    /// Starts the nameserver. `responder` sees each query and the transport
    /// it arrived on, and returns the response to send, if any.
    fn start<F>(responder: F) -> Result<Self, String>
    where
        F: Fn(&[u8], Transport) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        let (udp, tcp, addr) = bind_loopback_pair()?;
        udp.set_read_timeout(Some(Duration::from_millis(20)))
            .map_err(|err| format!("set loopback UDP read timeout: {err}"))?;
        tcp.set_nonblocking(true)
            .map_err(|err| format!("set loopback TCP listener nonblocking: {err}"))?;

        let responder = Arc::new(responder);
        let stop = Arc::new(AtomicBool::new(false));
        let queries = Arc::new(Mutex::new(Vec::new()));

        let udp_thread = {
            let responder = Arc::clone(&responder);
            let stop = Arc::clone(&stop);
            let queries = Arc::clone(&queries);
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while !stop.load(Ordering::Acquire) {
                    match udp.recv_from(&mut buf) {
                        Ok((len, peer)) => {
                            let query = buf[..len].to_vec();
                            record_query(&queries, Transport::Udp, &query);
                            if let Some(response) = (*responder)(&query[..], Transport::Udp) {
                                let _ = udp.send_to(&response, peer);
                            }
                        }
                        Err(err)
                            if matches!(
                                err.kind(),
                                io::ErrorKind::WouldBlock
                                    | io::ErrorKind::TimedOut
                                    | io::ErrorKind::Interrupted
                                    | io::ErrorKind::ConnectionReset
                            ) => {}
                        Err(_) => break,
                    }
                }
            })
        };

        let tcp_thread = {
            let responder = Arc::clone(&responder);
            let stop = Arc::clone(&stop);
            let queries = Arc::clone(&queries);
            thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    match tcp.accept() {
                        Ok((stream, _)) => {
                            let _ = serve_tcp_query(stream, &*responder, &queries);
                        }
                        Err(err)
                            if matches!(
                                err.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                            ) =>
                        {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            })
        };

        Ok(Self {
            addr,
            stop,
            queries,
            threads: vec![udp_thread, tcp_thread],
        })
    }

    /// Every query received so far, in arrival order.
    fn queries(&self) -> Vec<CapturedQuery> {
        self.queries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Drop for LoopbackNameserver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
    }
}

/// Binds a TCP listener and a UDP socket to the same loopback port.
fn bind_loopback_pair() -> Result<(UdpSocket, TcpListener, SocketAddr), String> {
    let mut last_error = String::from("no bind attempt was made");
    for _ in 0..64 {
        let tcp = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .map_err(|err| format!("bind loopback TCP nameserver: {err}"))?;
        let addr = tcp
            .local_addr()
            .map_err(|err| format!("read loopback TCP nameserver address: {err}"))?;
        match UdpSocket::bind(addr) {
            Ok(udp) => return Ok((udp, tcp, addr)),
            Err(err) => last_error = format!("bind loopback UDP nameserver on {addr}: {err}"),
        }
    }
    Err(last_error)
}

fn record_query(queries: &Mutex<Vec<CapturedQuery>>, transport: Transport, bytes: &[u8]) {
    queries
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(CapturedQuery {
            transport,
            bytes: bytes.to_vec(),
        });
}

/// Serves one length-prefixed DNS-over-TCP exchange (RFC 1035 Section 4.2.2).
fn serve_tcp_query<F>(
    mut stream: TcpStream,
    responder: &F,
    queries: &Mutex<Vec<CapturedQuery>>,
) -> io::Result<()>
where
    F: Fn(&[u8], Transport) -> Option<Vec<u8>>,
{
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(LOOKUP_TIMEOUT))?;
    stream.set_write_timeout(Some(LOOKUP_TIMEOUT))?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf)?;
    let mut query = vec![0u8; usize::from(u16::from_be_bytes(len_buf))];
    stream.read_exact(&mut query)?;
    record_query(queries, Transport::Tcp, &query);

    if let Some(response) = responder(&query[..], Transport::Tcp) {
        let frame_len = u16::try_from(response.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS response exceeds the 65535-octet TCP frame",
            )
        })?;
        stream.write_all(&frame_len.to_be_bytes())?;
        stream.write_all(&response)?;
    }
    Ok(())
}

/// Entropy source that makes every production query ID a fixed value.
#[derive(Debug, Clone, Copy)]
struct FixedQueryId(u16);

impl EntropySource for FixedQueryId {
    fn fill_bytes(&self, dest: &mut [u8]) {
        let id = self.0.to_be_bytes();
        for (index, byte) in dest.iter_mut().enumerate() {
            *byte = id[index % id.len()];
        }
    }

    fn next_u64(&self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fork(&self, _task_id: TaskId) -> Arc<dyn EntropySource> {
        Arc::new(*self)
    }

    fn source_id(&self) -> &'static str {
        "dns-conformance-fixed-query-id"
    }
}

/// A production resolver that sends every query, once, to `nameserver` with
/// ID `QUERY_ID` and no caching.
fn loopback_resolver(nameserver: SocketAddr) -> Resolver {
    Resolver::with_config(ResolverConfig {
        nameservers: vec![nameserver],
        cache_enabled: false,
        timeout: LOOKUP_TIMEOUT,
        retries: 0,
        ..ResolverConfig::default()
    })
    .with_entropy(Arc::new(FixedQueryId(QUERY_ID)))
}

fn lookup_ip_addrs(resolver: &Resolver, host: &str) -> Result<Vec<IpAddr>, DnsError> {
    let lookup = block_on(resolver.lookup_ip(host))?;
    Ok(lookup.addresses().to_vec())
}

fn lookup_mx_records(resolver: &Resolver, domain: &str) -> Result<Vec<(u16, String)>, DnsError> {
    let lookup = block_on(resolver.lookup_mx(domain))?;
    Ok(lookup
        .records()
        .map(|record| (record.preference, record.exchange.clone()))
        .collect())
}

fn lookup_txt_records(resolver: &Resolver, name: &str) -> Result<Vec<String>, DnsError> {
    let lookup = block_on(resolver.lookup_txt(name))?;
    Ok(lookup.records().map(str::to_string).collect())
}

/// Sends the AAAA and A queries of `lookup_ip`.
fn run_ip_lookup(resolver: &Resolver) {
    let _ = lookup_ip_addrs(resolver, "example.com");
}

/// Sends an MX query.
fn run_mx_lookup(resolver: &Resolver) {
    let _ = lookup_mx_records(resolver, "example.com");
}

/// Sends a TXT query.
fn run_txt_lookup(resolver: &Resolver) {
    let _ = lookup_txt_records(resolver, "example.com");
}

/// Sends every query type the public resolver can originate.
fn run_every_lookup(resolver: &Resolver) {
    run_ip_lookup(resolver);
    run_mx_lookup(resolver);
    run_txt_lookup(resolver);
}

/// Runs `run` against a nameserver that answers NODATA to everything and
/// returns the queries production sent.
fn capture_queries<L: FnOnce(&Resolver)>(run: L) -> Result<Vec<CapturedQuery>, String> {
    let server = LoopbackNameserver::start(|query: &[u8], _transport: Transport| {
        Some(create_dns_response_to_query(query, FLAGS_RESPONSE, &[]))
    })?;
    let resolver = loopback_resolver(server.addr);
    run(&resolver);
    let queries = server.queries();
    if queries.is_empty() {
        Err("production resolver sent no query to the loopback nameserver".to_string())
    } else {
        Ok(queries)
    }
}

/// A nameserver that replays each golden response to the exact production
/// query it answers, and NODATA to anything else.
fn start_golden_nameserver() -> Result<LoopbackNameserver, String> {
    let www_a_query = create_expected_resolver_query(QUERY_ID, "www.example.com", TYPE_A);
    let mx_query = create_expected_resolver_query(QUERY_ID, "example.com", TYPE_MX);
    LoopbackNameserver::start(move |query: &[u8], _transport: Transport| {
        if query == GOLDEN_A_QUERY {
            Some(GOLDEN_A_RESPONSE.to_vec())
        } else if query == www_a_query.as_slice() {
            Some(GOLDEN_CNAME_CHAIN_RESPONSE.to_vec())
        } else if query == mx_query.as_slice() {
            Some(GOLDEN_COMPRESSED_MX_RESPONSE.to_vec())
        } else {
            Some(create_dns_response_to_query(query, FLAGS_RESPONSE, &[]))
        }
    })
}

/// Answers the A query for example.com with `answers` (NODATA otherwise) and
/// returns what production's `lookup_ip` reports.
fn lookup_ip_with_a_answers(
    answers: Vec<Vec<u8>>,
) -> Result<Result<Vec<IpAddr>, DnsError>, String> {
    let server = LoopbackNameserver::start(move |query: &[u8], _transport: Transport| {
        let served: &[Vec<u8>] = if query == GOLDEN_A_QUERY {
            &answers
        } else {
            &[]
        };
        Some(create_dns_response_to_query(query, FLAGS_RESPONSE, served))
    })?;
    let resolver = loopback_resolver(server.addr);
    Ok(lookup_ip_addrs(&resolver, "example.com"))
}

/// Answers every MX query with `flags` (and, when `with_answer`, one MX
/// record) and returns what production's `lookup_mx` reports.
fn lookup_mx_with_response_flags(
    flags: u16,
    with_answer: bool,
) -> Result<Result<Vec<(u16, String)>, DnsError>, String> {
    let server = LoopbackNameserver::start(move |query: &[u8], _transport: Transport| {
        let answers = if with_answer {
            vec![create_mx_record(QNAME_PTR, 10, "mail.example.com")]
        } else {
            Vec::new()
        };
        Some(create_dns_response_to_query(query, flags, &answers))
    })?;
    let resolver = loopback_resolver(server.addr);
    Ok(lookup_mx_records(&resolver, "example.com"))
}

/// A response with RCODE `rcode` must surface as `DnsError::ServerError`.
fn expect_rcode_server_error(rcode: u16, name: &str) -> Result<(), String> {
    match lookup_mx_with_response_flags(FLAGS_RESPONSE | rcode, false)? {
        Err(DnsError::ServerError(_)) => Ok(()),
        other => Err(format!(
            "RCODE {rcode} ({name}) must surface as DnsError::ServerError from production \
             lookup_mx, got {other:?}"
        )),
    }
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
            let (status, detail_label) = match test.verdict {
                DnsTestVerdict::Pass => ("✅", "Error"),
                DnsTestVerdict::Fail => ("❌", "Error"),
                DnsTestVerdict::Skipped => ("⏭️", "Note"),
                DnsTestVerdict::ExpectedFailure => ("⚠️", "Note"),
            };
            report.push_str(&format!(
                "- {} **{}** ({}ms): {}\n",
                status, test.test_id, test.execution_time_ms, test.description
            ));

            if let Some(detail) = &test.error_message {
                report.push_str(&format!("  *{}: {}*\n", detail_label, detail));
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

        // Every requirement checked against production must hold.
        let failures: Vec<String> = results
            .iter()
            .filter(|r| r.verdict == DnsTestVerdict::Fail)
            .map(|r| {
                format!(
                    "{} ({}): {}",
                    r.test_id,
                    r.description,
                    r.error_message.as_deref().unwrap_or("no error message")
                )
            })
            .collect();
        assert!(
            failures.is_empty(),
            "production DNS code failed RFC 1035 requirements:\n{}",
            failures.join("\n")
        );

        // Requirements production cannot be driven to check are skipped, say
        // why, and are never counted as passes.
        let skipped: Vec<&str> = results
            .iter()
            .filter(|r| r.verdict == DnsTestVerdict::Skipped)
            .map(|r| r.test_id.as_str())
            .collect();
        assert_eq!(
            skipped,
            ["HFL003", "HFL006", "QTP006", "ADR001", "GLD002", "SIZ004"],
            "the set of requirements without a production observable changed"
        );
        for result in &results {
            if result.verdict == DnsTestVerdict::Skipped {
                assert!(
                    result
                        .error_message
                        .as_deref()
                        .is_some_and(|note| note.starts_with(SKIP_PREFIX)),
                    "{} is skipped without the no-observable note",
                    result.test_id
                );
            }
        }

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
    fn production_parser_accepts_header_only_response() {
        let packet = create_dns_response_packet(0x1234, FLAGS_RESPONSE, 0, 0, 0, 0);
        assert!(parse_dns_response_for_fuzz(&packet, 0x1234).is_ok());
    }

    #[test]
    fn production_parser_rejects_query_and_short_packets() {
        let query = create_dns_query_with_class(0x1234, "example.com", TYPE_A, CLASS_IN);
        assert!(matches!(
            parse_dns_response_for_fuzz(&query, 0x1234),
            Err(DnsError::Protocol(_))
        ));
        assert!(matches!(
            parse_dns_response_for_fuzz(&query[..11], 0x1234),
            Err(DnsError::Protocol(_))
        ));
    }

    #[test]
    fn production_name_decoder_rejects_name_past_end_of_packet() {
        let packet = create_basic_dns_packet();
        let mut offset = 12;
        assert!(matches!(
            decode_dns_name_for_fuzz(&packet, &mut offset),
            Err(DnsError::Protocol(_))
        ));
    }

    #[test]
    fn golden_responses_parse_through_production() {
        for (label, golden) in [
            ("A answer", GOLDEN_A_RESPONSE),
            ("CNAME chain", GOLDEN_CNAME_CHAIN_RESPONSE),
            ("compressed MX", GOLDEN_COMPRESSED_MX_RESPONSE),
            ("OPT additional record", GOLDEN_OPT_RESPONSE),
        ] {
            assert!(
                parse_dns_response_for_fuzz(golden, QUERY_ID).is_ok(),
                "{label} golden rejected by production"
            );
        }
        assert_eq!(
            create_a_response(QUERY_ID),
            GOLDEN_A_RESPONSE,
            "the A-response builder and its golden diverged"
        );
    }
}
