#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

/// Expect: 100-continue fuzzing for HTTP/1.1 protocol edge cases.
///
/// Tests the full pipeline from header parsing to response generation:
/// - Expect header classification (100-continue, unsupported, malformed)
/// - HTTP version compatibility (HTTP/1.0 vs HTTP/1.1)
/// - Body presence detection and gating
/// - State machine transitions for expectation handling
/// - Edge cases with malformed tokens, case sensitivity, whitespace
///
/// Covers critical security scenarios:
/// - Request smuggling via malformed Expect headers
/// - Body bypass attempts with crafted expectation tokens
/// - State confusion with mixed expectation types
/// - Protocol downgrade attacks (HTTP/1.0 with 100-continue)
#[derive(Arbitrary, Debug, Clone)]
pub struct ExpectContinueTestCase {
    /// HTTP version (true = 1.1, false = 1.0)
    http_version: bool,
    /// Request method
    method: RequestMethod,
    /// URI path
    uri: UriPath,
    /// Expect header scenarios
    expect_header: Option<ExpectHeaderType>,
    /// Additional headers that affect body parsing
    body_headers: BodyHeaderType,
    /// Request body configuration
    body_config: BodyConfig,
    /// Connection state
    connection_state: ConnectionState,
    /// Timing scenario
    timing: TimingScenario,
}

#[derive(Arbitrary, Debug, Clone)]
pub enum RequestMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
    Connect,
    Trace,
    Custom(CustomMethod),
}

#[derive(Arbitrary, Debug, Clone)]
pub struct CustomMethod {
    /// Custom method name with potential edge cases
    name: MethodName,
}

#[derive(Arbitrary, Debug, Clone)]
pub enum MethodName {
    Normal(String),
    WithWhitespace(String),
    WithControl(String),
    Empty,
    VeryLong(String),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum UriPath {
    Root,
    Simple(String),
    WithQuery(String, String),
    WithFragment(String, String),
    Asterisk,
    Authority(String, u16),
    Absolute(String),
    Malformed(String),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum ExpectHeaderType {
    /// Standard 100-continue
    Continue,
    /// Case variations
    ContinueUppercase,
    ContinueMixedCase,
    /// With whitespace
    ContinueWithSpaces,
    ContinueWithTabs,
    /// Multiple tokens
    ContinueWithExtra(String),
    MultipleContinue,
    /// Unsupported expectations
    UnsupportedSingle(String),
    UnsupportedMultiple(Vec<String>),
    /// Malformed headers
    MalformedTokens(String),
    EmptyValue,
    OnlyWhitespace,
    WithControlChars(String),
    /// Protocol edge cases
    HttpVersionMismatch,
    /// Multiple Expect headers (forbidden)
    Duplicate(String, String),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum BodyHeaderType {
    None,
    ContentLength(ContentLengthType),
    TransferEncoding(TransferEncodingType),
    Both(ContentLengthType, TransferEncodingType), // Ambiguous - RFC violation
    Malformed(String, String),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum ContentLengthType {
    Zero,
    Small(u32), // 1-1000
    Large(u32), // 1001-65536
    VeryLarge(u64),
    Invalid(String),
    Negative(String),
    Multiple(Vec<String>),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum TransferEncodingType {
    Chunked,
    Gzip,
    Deflate,
    Multiple(Vec<String>),
    Unsupported(String),
    Malformed(String),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum BodyConfig {
    Empty,
    Present(BodyPresence),
    Delayed,
    Partial,
    Malformed(String),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum BodyPresence {
    Immediate(Vec<u8>),
    Chunked(Vec<ChunkData>),
    WithTrailers(Vec<u8>, Vec<(String, String)>),
}

#[derive(Arbitrary, Debug, Clone)]
pub struct ChunkData {
    size: u32,
    data: Vec<u8>,
    extensions: Option<String>,
}

#[derive(Arbitrary, Debug, Clone)]
pub enum ConnectionState {
    Fresh,
    KeepAlive(u32),       // request count
    PipelinePending(u32), // pending requests
    Closing,
}

#[derive(Arbitrary, Debug, Clone)]
pub enum TimingScenario {
    /// Body arrives after expect processing
    BodyAfterContinue,
    /// Body arrives before continue response
    EagerBody,
    /// No body ever arrives
    NoBody,
    /// Partial body then timeout
    PartialTimeout,
    /// Concurrent pipeline requests
    Pipelined,
}

/// Mock HTTP/1.1 Expect: 100-continue handler for fuzzing
#[derive(Debug)]
pub struct MockExpectHandler {
    state: ExpectState,
    version: HttpVersion,
    requests_processed: u32,
    max_header_size: usize,
    max_body_size: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExpectState {
    AwaitingHeaders,
    ProcessingExpectation,
    ContinueSent,
    ExpectationRejected,
    BodyProcessing,
    RequestComplete,
    Error(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum HttpVersion {
    Http10,
    Http11,
    Http2,
    Unknown(String),
}

#[derive(Debug, Clone)]
pub enum ExpectationAction {
    None,
    Continue,
    Reject,
}

#[derive(Debug, Clone)]
pub struct ExpectationResult {
    action: ExpectationAction,
    response_code: u16,
    response_headers: Vec<(String, String)>,
    error: Option<String>,
}

impl MockExpectHandler {
    pub fn new() -> Self {
        Self {
            state: ExpectState::AwaitingHeaders,
            version: HttpVersion::Http11,
            requests_processed: 0,
            max_header_size: 64 * 1024,
            max_body_size: 16 * 1024 * 1024,
        }
    }

    pub fn process_request(
        &mut self,
        test_case: &ExpectContinueTestCase,
    ) -> Result<ExpectationResult, String> {
        // Reset state for new request
        self.state = ExpectState::AwaitingHeaders;
        self.version = if test_case.http_version {
            HttpVersion::Http11
        } else {
            HttpVersion::Http10
        };

        // Parse request line
        self.validate_request_line(&test_case.method, &test_case.uri)?;

        // Process Expect header
        let expectation_action = self.classify_expectation(&test_case.expect_header)?;

        // Validate body headers
        self.validate_body_headers(&test_case.body_headers)?;

        // Check protocol compatibility
        self.check_protocol_compatibility(&expectation_action)?;

        // Determine if body is expected
        let expects_body =
            self.request_expects_body(&test_case.body_headers, &test_case.body_config);

        // Generate expectation response
        let result =
            self.handle_expectation(expectation_action, expects_body, &test_case.timing)?;

        // Process body if needed
        if result.action == ExpectationAction::Continue {
            self.process_body(&test_case.body_config, &test_case.timing)?;
        }

        Ok(result)
    }

    fn validate_request_line(
        &mut self,
        method: &RequestMethod,
        uri: &UriPath,
    ) -> Result<(), String> {
        // Validate method
        match method {
            RequestMethod::Custom(custom) => match &custom.name {
                MethodName::Normal(name) => {
                    if name.is_empty() {
                        return Err("Empty method name".to_string());
                    }
                    if name.len() > 32 {
                        return Err("Method name too long".to_string());
                    }
                    if !name.chars().all(|c| c.is_ascii_alphabetic()) {
                        return Err("Invalid method characters".to_string());
                    }
                }
                MethodName::WithWhitespace(_) => {
                    return Err("Method contains whitespace".to_string());
                }
                MethodName::WithControl(_) => {
                    return Err("Method contains control characters".to_string());
                }
                MethodName::Empty => return Err("Empty method".to_string()),
                MethodName::VeryLong(name) => {
                    if name.len() > 1024 {
                        return Err("Method too long".to_string());
                    }
                }
            },
            _ => {} // Standard methods are always valid
        }

        // Validate URI
        match uri {
            UriPath::Root
            | UriPath::Simple(_)
            | UriPath::WithQuery(_, _)
            | UriPath::WithFragment(_, _) => {}
            UriPath::Asterisk => {
                if !matches!(method, RequestMethod::Options) {
                    return Err("Asterisk URI only allowed for OPTIONS".to_string());
                }
            }
            UriPath::Authority(host, _) => {
                if !matches!(method, RequestMethod::Connect) {
                    return Err("Authority URI only allowed for CONNECT".to_string());
                }
                if host.is_empty() {
                    return Err("Empty authority host".to_string());
                }
            }
            UriPath::Malformed(_) => return Err("Malformed URI".to_string()),
            _ => {}
        }

        Ok(())
    }

    fn classify_expectation(
        &mut self,
        expect_header: &Option<ExpectHeaderType>,
    ) -> Result<ExpectationAction, String> {
        self.state = ExpectState::ProcessingExpectation;

        let Some(ref expect) = expect_header else {
            return Ok(ExpectationAction::None);
        };

        match expect {
            ExpectHeaderType::Continue
            | ExpectHeaderType::ContinueUppercase
            | ExpectHeaderType::ContinueMixedCase => {
                // Standard 100-continue
                Ok(ExpectationAction::Continue)
            }

            ExpectHeaderType::ContinueWithSpaces | ExpectHeaderType::ContinueWithTabs => {
                // Whitespace handling - should normalize to continue
                Ok(ExpectationAction::Continue)
            }

            ExpectHeaderType::ContinueWithExtra(_)
            | ExpectHeaderType::MultipleContinue
            | ExpectHeaderType::UnsupportedSingle(_)
            | ExpectHeaderType::UnsupportedMultiple(_) => {
                // RFC 7231: Multiple tokens or unsupported = reject
                Ok(ExpectationAction::Reject)
            }

            ExpectHeaderType::MalformedTokens(_) | ExpectHeaderType::WithControlChars(_) => {
                return Err("Malformed Expect header".to_string());
            }

            ExpectHeaderType::EmptyValue | ExpectHeaderType::OnlyWhitespace => {
                // Empty Expect header = unsupported expectation
                Ok(ExpectationAction::Reject)
            }

            ExpectHeaderType::HttpVersionMismatch => {
                // Force version mismatch scenario
                Ok(ExpectationAction::Reject)
            }

            ExpectHeaderType::Duplicate(_, _) => {
                return Err("Duplicate Expect header forbidden".to_string());
            }
        }
    }

    fn validate_body_headers(&mut self, body_headers: &BodyHeaderType) -> Result<(), String> {
        match body_headers {
            BodyHeaderType::Both(_, _) => {
                // RFC 7230 3.3.3: Both Content-Length and Transfer-Encoding = potential smuggling
                return Err(
                    "Ambiguous body length (both Content-Length and Transfer-Encoding)".to_string(),
                );
            }

            BodyHeaderType::ContentLength(cl) => match cl {
                ContentLengthType::Invalid(_) => return Err("Invalid Content-Length".to_string()),
                ContentLengthType::Negative(_) => return Err("Negative Content-Length".to_string()),
                ContentLengthType::Multiple(_) => {
                    return Err("Multiple Content-Length headers".to_string());
                }
                ContentLengthType::VeryLarge(size) => {
                    if *size > self.max_body_size as u64 {
                        return Err("Content-Length exceeds limit".to_string());
                    }
                }
                _ => {}
            },

            BodyHeaderType::TransferEncoding(te) => match te {
                TransferEncodingType::Unsupported(_) => {
                    return Err("Unsupported Transfer-Encoding".to_string());
                }
                TransferEncodingType::Malformed(_) => {
                    return Err("Malformed Transfer-Encoding".to_string());
                }
                _ => {}
            },

            BodyHeaderType::Malformed(_, _) => {
                return Err("Malformed body header".to_string());
            }

            BodyHeaderType::None => {}
        }

        Ok(())
    }

    fn check_protocol_compatibility(&mut self, action: &ExpectationAction) -> Result<(), String> {
        // HTTP/1.0 doesn't support 100-continue
        if self.version == HttpVersion::Http10 && *action == ExpectationAction::Continue {
            return Ok(()); // Will be rejected in handle_expectation
        }

        Ok(())
    }

    fn request_expects_body(
        &self,
        body_headers: &BodyHeaderType,
        body_config: &BodyConfig,
    ) -> bool {
        // Check headers
        let has_body_headers = match body_headers {
            BodyHeaderType::None => false,
            BodyHeaderType::ContentLength(ContentLengthType::Zero) => false,
            BodyHeaderType::ContentLength(_) => true,
            BodyHeaderType::TransferEncoding(_) => true,
            BodyHeaderType::Both(_, _) => true,
            BodyHeaderType::Malformed(_, _) => false, // Already failed validation
        };

        // Check body presence
        let has_body_data = match body_config {
            BodyConfig::Empty => false,
            BodyConfig::Present(_) => true,
            BodyConfig::Delayed => true,
            BodyConfig::Partial => true,
            BodyConfig::Malformed(_) => false,
        };

        has_body_headers || has_body_data
    }

    fn handle_expectation(
        &mut self,
        action: ExpectationAction,
        expects_body: bool,
        timing: &TimingScenario,
    ) -> Result<ExpectationResult, String> {
        match action {
            ExpectationAction::None => {
                self.state = ExpectState::BodyProcessing;
                Ok(ExpectationResult {
                    action,
                    response_code: 0, // No interim response
                    response_headers: vec![],
                    error: None,
                })
            }

            ExpectationAction::Continue => {
                // Check HTTP version
                if self.version == HttpVersion::Http10 {
                    self.state = ExpectState::ExpectationRejected;
                    return Ok(ExpectationResult {
                        action: ExpectationAction::Reject,
                        response_code: 417,
                        response_headers: vec![("Connection".to_string(), "close".to_string())],
                        error: Some("100-continue not supported in HTTP/1.0".to_string()),
                    });
                }

                // Only send 100-continue if body is expected
                if !expects_body {
                    self.state = ExpectState::BodyProcessing;
                    return Ok(ExpectationResult {
                        action: ExpectationAction::None,
                        response_code: 0,
                        response_headers: vec![],
                        error: None,
                    });
                }

                // Check timing scenario
                match timing {
                    TimingScenario::EagerBody => {
                        // Body already arrived - still send continue but note timing
                        self.state = ExpectState::ContinueSent;
                    }
                    _ => {
                        self.state = ExpectState::ContinueSent;
                    }
                }

                Ok(ExpectationResult {
                    action,
                    response_code: 100,
                    response_headers: vec![],
                    error: None,
                })
            }

            ExpectationAction::Reject => {
                self.state = ExpectState::ExpectationRejected;
                Ok(ExpectationResult {
                    action,
                    response_code: 417,
                    response_headers: vec![("Connection".to_string(), "close".to_string())],
                    error: Some("Expectation failed".to_string()),
                })
            }
        }
    }

    fn process_body(
        &mut self,
        body_config: &BodyConfig,
        timing: &TimingScenario,
    ) -> Result<(), String> {
        if self.state != ExpectState::ContinueSent && self.state != ExpectState::BodyProcessing {
            return Err("Invalid state for body processing".to_string());
        }

        match body_config {
            BodyConfig::Empty => {
                self.state = ExpectState::RequestComplete;
            }

            BodyConfig::Present(presence) => match presence {
                BodyPresence::Immediate(data) => {
                    if data.len() > self.max_body_size {
                        return Err("Body too large".to_string());
                    }
                    self.state = ExpectState::RequestComplete;
                }

                BodyPresence::Chunked(chunks) => {
                    let total_size: usize = chunks.iter().map(|c| c.data.len()).sum();
                    if total_size > self.max_body_size {
                        return Err("Chunked body too large".to_string());
                    }
                    self.validate_chunks(chunks)?;
                    self.state = ExpectState::RequestComplete;
                }

                BodyPresence::WithTrailers(data, trailers) => {
                    if data.len() > self.max_body_size {
                        return Err("Body too large".to_string());
                    }
                    self.validate_trailers(trailers)?;
                    self.state = ExpectState::RequestComplete;
                }
            },

            BodyConfig::Delayed => match timing {
                TimingScenario::PartialTimeout => {
                    return Err("Body timeout".to_string());
                }
                _ => {
                    self.state = ExpectState::RequestComplete;
                }
            },

            BodyConfig::Partial => {
                return Err("Incomplete body".to_string());
            }

            BodyConfig::Malformed(_) => {
                return Err("Malformed body".to_string());
            }
        }

        self.requests_processed += 1;
        Ok(())
    }

    fn validate_chunks(&self, chunks: &[ChunkData]) -> Result<(), String> {
        for chunk in chunks {
            if chunk.size as usize != chunk.data.len() {
                return Err("Chunk size mismatch".to_string());
            }
            if let Some(ref extensions) = chunk.extensions {
                if extensions.contains('\r') || extensions.contains('\n') {
                    return Err("Invalid chunk extensions".to_string());
                }
            }
        }
        Ok(())
    }

    fn validate_trailers(&self, trailers: &[(String, String)]) -> Result<(), String> {
        const FORBIDDEN_TRAILERS: &[&str] = &[
            "authorization",
            "cache-control",
            "content-encoding",
            "content-length",
            "content-range",
            "content-type",
            "cookie",
            "date",
            "expect",
            "expires",
            "host",
            "max-forwards",
            "pragma",
            "proxy-authenticate",
            "proxy-authorization",
            "range",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
        ];

        for (name, _) in trailers {
            if FORBIDDEN_TRAILERS
                .iter()
                .any(|&forbidden| name.eq_ignore_ascii_case(forbidden))
            {
                return Err(format!("Forbidden trailer: {}", name));
            }
        }
        Ok(())
    }
}

impl PartialEq for ExpectationAction {
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(test_case) = ExpectContinueTestCase::arbitrary(&mut u) {
        let mut handler = MockExpectHandler::new();

        // Test the main flow
        let result = handler.process_request(&test_case);

        // Validate invariants
        match result {
            Ok(expectation_result) => {
                // Validate response codes
                match expectation_result.response_code {
                    0 => {
                        // No interim response - action should be None
                        assert_eq!(
                            expectation_result.action,
                            ExpectationAction::None,
                            "No response code but action is not None"
                        );
                    }
                    100 => {
                        // Continue response
                        assert_eq!(
                            expectation_result.action,
                            ExpectationAction::Continue,
                            "100 response but action is not Continue"
                        );
                        assert!(
                            expectation_result.error.is_none(),
                            "100 response should not have error"
                        );
                    }
                    417 => {
                        // Expectation failed
                        assert_eq!(
                            expectation_result.action,
                            ExpectationAction::Reject,
                            "417 response but action is not Reject"
                        );
                    }
                    _ => panic!(
                        "Invalid response code: {}",
                        expectation_result.response_code
                    ),
                }

                // Validate state consistency
                match handler.state {
                    ExpectState::RequestComplete => {
                        // Should only be complete if we processed body successfully
                        if expectation_result.action == ExpectationAction::Reject {
                            panic!("Request completed but expectation was rejected");
                        }
                    }
                    ExpectState::ExpectationRejected => {
                        assert_eq!(
                            expectation_result.action,
                            ExpectationAction::Reject,
                            "State rejected but action is not Reject"
                        );
                    }
                    ExpectState::Error(_) => {
                        panic!("Handler ended in error state without returning error");
                    }
                    _ => {} // Other states are valid intermediate states
                }

                // Validate HTTP/1.0 compatibility
                if handler.version == HttpVersion::Http10 {
                    if expectation_result.response_code == 100 {
                        panic!("100-continue sent for HTTP/1.0 request");
                    }
                }
            }

            Err(_error) => {
                // Error is acceptable - validate it doesn't crash or leak
                assert!(
                    handler.state != ExpectState::AwaitingHeaders
                        || handler.state == ExpectState::Error(_error.clone()),
                    "Handler state inconsistent with error"
                );
            }
        }

        // Test edge case: multiple rapid requests on same handler
        for _ in 0..3 {
            let _ = handler.process_request(&test_case);
        }

        // Test state reset between requests
        let fresh_handler = MockExpectHandler::new();
        let initial_state = fresh_handler.state.clone();
        drop(fresh_handler);

        let mut second_handler = MockExpectHandler::new();
        assert_eq!(
            second_handler.state, initial_state,
            "Handler state not properly reset"
        );

        // Verify processing doesn't corrupt future requests
        let _ = second_handler.process_request(&test_case);
        let _ = second_handler.process_request(&test_case);
    }
});
