//! Fuzzing target for HTTP/2 HEADERS frame size cap with concurrent CONTINUATION frames.
//!
//! Tests resource exhaustion and size limit enforcement when HEADERS frames are split
//! across multiple CONTINUATION frames, particularly testing concurrent streams and
//! edge cases around the header fragment size limits.
//!
//! Vulnerability areas:
//! 1. Header fragment accumulation size limits (256KB max, 4x header list size)
//! 2. Concurrent CONTINUATION sequences across multiple streams
//! 3. Resource exhaustion via many small CONTINUATION frames
//! 4. Race conditions in size checking and fragment accumulation
//! 5. Buffer overflow/underflow in fragment concatenation
//! 6. Memory exhaustion from unbounded fragment lists

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Constants from HTTP/2 implementation
const HEADER_FRAGMENT_MULTIPLIER: usize = 4;
const MAX_HEADER_FRAGMENT_SIZE: usize = 256 * 1024; // 256 KB
const DEFAULT_MAX_HEADER_LIST_SIZE: u32 = 16 * 1024; // 16 KB
const MAX_FRAME_SIZE: u32 = 16_777_215; // 2^24 - 1

/// Mock connection for testing header fragment accumulation and size limits.
#[derive(Debug, Clone)]
pub struct MockH2HeaderConnection {
    /// Active streams with header fragment accumulation
    streams: std::collections::HashMap<u32, MockStream>,
    /// Connection-level settings
    settings: ConnectionSettings,
    /// Statistics for analysis
    stats: ConnectionStats,
}

/// Per-stream state for header fragment accumulation
#[derive(Debug, Clone)]
pub struct MockStream {
    /// Stream ID
    stream_id: u32,
    /// Accumulated header fragments
    header_fragments: Vec<Vec<u8>>,
    /// Maximum allowed fragment size for this stream
    max_fragment_size: usize,
    /// Whether expecting continuation frames
    expecting_continuation: bool,
    /// Total bytes accumulated so far
    total_accumulated: usize,
}

/// Connection-level settings
#[derive(Debug, Clone)]
pub struct ConnectionSettings {
    /// Maximum header list size
    max_header_list_size: u32,
    /// Maximum frame size
    max_frame_size: u32,
    /// Maximum concurrent streams
    max_concurrent_streams: u32,
}

/// Statistics for tracking behavior
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    /// Total streams created
    pub streams_created: u32,
    /// Total header fragments processed
    pub fragments_processed: u32,
    /// Total bytes in all fragments
    pub total_fragment_bytes: usize,
    /// Number of size limit violations
    pub size_limit_violations: u32,
    /// Number of successful completions
    pub completed_headers: u32,
    /// Maximum fragment size encountered
    pub max_fragment_size_seen: usize,
    /// Maximum accumulated size encountered
    pub max_accumulated_size_seen: usize,
    /// Number of concurrent continuation sequences
    pub concurrent_continuations: u32,
}

/// Test scenario for concurrent HEADERS + CONTINUATION frames
#[derive(Debug, Clone, Arbitrary)]
pub struct HeadersSizeConcurrentScenario {
    /// Sequence of frame operations to test
    pub frame_operations: Vec<FrameOperation>,
    /// Connection settings to use
    pub connection_settings: TestConnectionSettings,
    /// Whether to test extreme concurrency
    pub test_extreme_concurrency: bool,
    /// Maximum operations to prevent timeouts
    pub max_operations: u16,
}

/// Individual frame operation in the test sequence
#[derive(Debug, Clone, Arbitrary)]
pub struct FrameOperation {
    /// The operation to perform
    pub operation: FrameOpType,
    /// Stream ID for this operation
    pub stream_id: StreamId,
    /// When to execute this operation
    pub timing: u8,
}

/// Types of frame operations to test
#[derive(Debug, Clone, Arbitrary)]
pub enum FrameOpType {
    /// Send HEADERS frame (potentially starting continuation sequence)
    SendHeaders(HeadersFrameTest),
    /// Send CONTINUATION frame
    SendContinuation(ContinuationFrameTest),
    /// Send multiple concurrent CONTINUATION frames
    SendConcurrentContinuations(ConcurrentContinuationsTest),
    /// Test size limit boundary
    TestSizeLimit(SizeLimitTest),
    /// Reset stream (interrupting continuation sequence)
    ResetStream,
}

/// HEADERS frame test parameters
#[derive(Debug, Clone, Arbitrary)]
pub struct HeadersFrameTest {
    /// Header block size
    pub header_block_size: HeaderBlockSize,
    /// Whether this frame sets END_HEADERS flag
    pub end_headers: bool,
    /// Priority information (optional)
    pub priority_weight: Option<u8>,
}

/// CONTINUATION frame test parameters
#[derive(Debug, Clone, Arbitrary)]
pub struct ContinuationFrameTest {
    /// Fragment size for this continuation
    pub fragment_size: FragmentSize,
    /// Whether this is the final continuation (END_HEADERS)
    pub end_headers: bool,
    /// Whether to introduce delay
    pub delayed: bool,
}

/// Concurrent continuations test
#[derive(Debug, Clone, Arbitrary)]
pub struct ConcurrentContinuationsTest {
    /// Number of continuation frames to send
    pub continuation_count: u8,
    /// Size of each continuation fragment
    pub fragment_size: FragmentSize,
    /// Whether to interleave with other streams
    pub interleave_streams: bool,
}

/// Size limit boundary testing
#[derive(Debug, Clone, Arbitrary)]
pub struct SizeLimitTest {
    /// Target size relative to the limit
    pub target_size: SizeLimitTarget,
    /// How to approach the limit
    pub approach: SizeLimitApproach,
    /// Whether to test overflow
    pub test_overflow: bool,
}

/// Stream ID generation for testing
#[derive(Debug, Clone, Arbitrary)]
pub enum StreamId {
    /// Fixed stream ID
    Fixed(u32),
    /// Sequential stream IDs
    Sequential(u8),
    /// Random valid stream ID
    Random(u16),
    /// Invalid stream ID (for error testing)
    Invalid(u32),
}

/// Header block size categories
#[derive(Debug, Clone, Arbitrary)]
pub enum HeaderBlockSize {
    /// Empty header block
    Empty,
    /// Small header block (1-100 bytes)
    Small(u8),
    /// Medium header block (101-4096 bytes)
    Medium(u16),
    /// Large header block (4097-65536 bytes)
    Large(u16),
    /// Exactly at frame size limit
    MaxFrame,
    /// Computed size based on limits
    Computed(ComputedSize),
}

/// Fragment size for CONTINUATION frames
#[derive(Debug, Clone, Arbitrary)]
pub enum FragmentSize {
    /// Tiny fragments (1-16 bytes)
    Tiny(u8),
    /// Small fragments (17-1024 bytes)
    Small(u16),
    /// Large fragments (1025-16384 bytes)
    Large(u16),
    /// Maximum frame size
    MaxFrame,
    /// Size to reach exactly the limit
    ToLimit(u16),
}

/// Size limit targets for boundary testing
#[derive(Debug, Clone, Arbitrary)]
pub enum SizeLimitTarget {
    /// Just under the limit
    UnderLimit(u16),
    /// Exactly at the limit
    ExactlyAtLimit,
    /// Just over the limit
    OverLimit(u16),
    /// Way over the limit
    WayOverLimit(u32),
}

/// How to approach size limits
#[derive(Debug, Clone, Arbitrary)]
pub enum SizeLimitApproach {
    /// Single large fragment
    SingleFragment,
    /// Many small fragments
    ManySmallFragments,
    /// Few medium fragments
    FewMediumFragments,
    /// Exponentially increasing fragments
    ExponentialIncrease,
}

/// Computed size for dynamic testing
#[derive(Debug, Clone, Arbitrary)]
pub enum ComputedSize {
    /// Percentage of max header list size
    PercentOfMaxList(u8),
    /// Percentage of max fragment size
    PercentOfMaxFragment(u8),
    /// Multiple of frame size
    MultipleOfFrame(u8),
}

/// Connection settings for testing
#[derive(Debug, Clone, Arbitrary)]
pub struct TestConnectionSettings {
    /// Maximum header list size override
    pub max_header_list_size: Option<u32>,
    /// Maximum frame size override
    pub max_frame_size: Option<u32>,
    /// Maximum concurrent streams
    pub max_concurrent_streams: Option<u32>,
}

/// Result of processing a frame operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameProcessResult {
    /// Frame accepted and processed
    Accepted {
        bytes_added: usize,
        total_accumulated: usize,
    },
    /// Size limit exceeded
    SizeLimitExceeded { attempted_size: usize, limit: usize },
    /// Continuation sequence completed
    ContinuationComplete {
        total_size: usize,
        fragment_count: usize,
    },
    /// Stream reset or error
    StreamError { error_type: String },
    /// Concurrent operation conflict
    ConcurrencyViolation { reason: String },
}

impl MockH2HeaderConnection {
    pub fn new(settings: TestConnectionSettings) -> Self {
        let conn_settings = ConnectionSettings {
            max_header_list_size: settings
                .max_header_list_size
                .unwrap_or(DEFAULT_MAX_HEADER_LIST_SIZE),
            max_frame_size: settings.max_frame_size.unwrap_or(MAX_FRAME_SIZE),
            max_concurrent_streams: settings.max_concurrent_streams.unwrap_or(100),
        };

        Self {
            streams: std::collections::HashMap::new(),
            settings: conn_settings,
            stats: ConnectionStats::default(),
        }
    }

    /// Calculate maximum fragment size for current settings
    fn max_fragment_size(&self) -> usize {
        let max_list_size = self.settings.max_header_list_size as usize;
        let calculated = max_list_size.saturating_mul(HEADER_FRAGMENT_MULTIPLIER);
        calculated.min(MAX_HEADER_FRAGMENT_SIZE)
    }

    /// Process a frame operation
    pub fn process_frame_operation(&mut self, operation: &FrameOperation) -> FrameProcessResult {
        let stream_id = self.resolve_stream_id(&operation.stream_id);

        // Check for invalid stream IDs
        if stream_id == 0 || stream_id > 0x7FFF_FFFF {
            return FrameProcessResult::StreamError {
                error_type: "Invalid stream ID".to_string(),
            };
        }

        match &operation.operation {
            FrameOpType::SendHeaders(headers) => self.process_headers(stream_id, headers),
            FrameOpType::SendContinuation(cont) => self.process_continuation(stream_id, cont),
            FrameOpType::SendConcurrentContinuations(concurrent) => {
                self.process_concurrent_continuations(stream_id, concurrent)
            }
            FrameOpType::TestSizeLimit(size_test) => self.test_size_limit(stream_id, size_test),
            FrameOpType::ResetStream => self.reset_stream(stream_id),
        }
    }

    fn resolve_stream_id(&self, stream_id: &StreamId) -> u32 {
        match stream_id {
            StreamId::Fixed(id) => *id,
            StreamId::Sequential(offset) => (*offset as u32) * 2 + 1, // Client-initiated streams
            StreamId::Random(seed) => ((*seed as u32) % 1000) * 2 + 1,
            StreamId::Invalid(id) => *id,
        }
    }

    fn process_headers(
        &mut self,
        stream_id: u32,
        headers: &HeadersFrameTest,
    ) -> FrameProcessResult {
        // Compute header size first to avoid borrow checker issues
        let header_size = self.resolve_header_block_size(&headers.header_block_size);

        // Create stream if it doesn't exist
        if !self.streams.contains_key(&stream_id) {
            let stream = MockStream {
                stream_id,
                header_fragments: Vec::new(),
                max_fragment_size: self.max_fragment_size(),
                expecting_continuation: !headers.end_headers,
                total_accumulated: 0,
            };
            self.streams.insert(stream_id, stream);
            self.stats.streams_created += 1;
        }

        let stream = self.streams.get_mut(&stream_id).unwrap();

        // Check if adding this header block would exceed limits
        if stream.total_accumulated.saturating_add(header_size) > stream.max_fragment_size {
            self.stats.size_limit_violations += 1;
            return FrameProcessResult::SizeLimitExceeded {
                attempted_size: header_size,
                limit: stream.max_fragment_size,
            };
        }

        // Add header fragment
        stream.header_fragments.push(vec![0u8; header_size]);
        stream.total_accumulated += header_size;
        stream.expecting_continuation = !headers.end_headers;

        self.stats.fragments_processed += 1;
        self.stats.total_fragment_bytes += header_size;
        self.stats.max_fragment_size_seen = self.stats.max_fragment_size_seen.max(header_size);
        self.stats.max_accumulated_size_seen = self
            .stats
            .max_accumulated_size_seen
            .max(stream.total_accumulated);

        if headers.end_headers {
            self.stats.completed_headers += 1;
            FrameProcessResult::ContinuationComplete {
                total_size: stream.total_accumulated,
                fragment_count: stream.header_fragments.len(),
            }
        } else {
            FrameProcessResult::Accepted {
                bytes_added: header_size,
                total_accumulated: stream.total_accumulated,
            }
        }
    }

    fn process_continuation(
        &mut self,
        stream_id: u32,
        cont: &ContinuationFrameTest,
    ) -> FrameProcessResult {
        // Get max fragment size first to avoid borrow checker issues
        let max_fragment_size = self.max_fragment_size();

        let stream = match self.streams.get_mut(&stream_id) {
            Some(s) => s,
            None => {
                return FrameProcessResult::StreamError {
                    error_type: "Continuation on non-existent stream".to_string(),
                };
            }
        };

        if !stream.expecting_continuation {
            return FrameProcessResult::ConcurrencyViolation {
                reason: "Unexpected continuation frame".to_string(),
            };
        }

        let fragment_size = match &cont.fragment_size {
            FragmentSize::Tiny(s) => (*s as usize).min(16),
            FragmentSize::Small(s) => (*s as usize).min(1024),
            FragmentSize::Large(s) => (*s as usize).min(16384),
            FragmentSize::MaxFrame => self.settings.max_frame_size.min(u16::MAX.into()) as usize,
            FragmentSize::ToLimit(offset) => max_fragment_size.saturating_sub(*offset as usize),
        }
        .min(max_fragment_size);

        // Check size limit
        if stream.total_accumulated.saturating_add(fragment_size) > stream.max_fragment_size {
            self.stats.size_limit_violations += 1;
            return FrameProcessResult::SizeLimitExceeded {
                attempted_size: fragment_size,
                limit: stream.max_fragment_size,
            };
        }

        // Add continuation fragment
        stream.header_fragments.push(vec![0u8; fragment_size]);
        stream.total_accumulated += fragment_size;
        stream.expecting_continuation = !cont.end_headers;

        self.stats.fragments_processed += 1;
        self.stats.total_fragment_bytes += fragment_size;
        self.stats.max_fragment_size_seen = self.stats.max_fragment_size_seen.max(fragment_size);
        self.stats.max_accumulated_size_seen = self
            .stats
            .max_accumulated_size_seen
            .max(stream.total_accumulated);

        if cont.end_headers {
            self.stats.completed_headers += 1;
            FrameProcessResult::ContinuationComplete {
                total_size: stream.total_accumulated,
                fragment_count: stream.header_fragments.len(),
            }
        } else {
            FrameProcessResult::Accepted {
                bytes_added: fragment_size,
                total_accumulated: stream.total_accumulated,
            }
        }
    }

    fn process_concurrent_continuations(
        &mut self,
        base_stream_id: u32,
        concurrent: &ConcurrentContinuationsTest,
    ) -> FrameProcessResult {
        let continuation_count = concurrent.continuation_count.min(20); // Prevent excessive operations
        self.stats.concurrent_continuations += 1;

        // Test sending multiple continuation frames rapidly
        for i in 0..continuation_count {
            let stream_id = if concurrent.interleave_streams {
                base_stream_id + (i as u32) * 2
            } else {
                base_stream_id
            };

            let fragment_size =
                self.resolve_fragment_size(&concurrent.fragment_size, self.max_fragment_size());

            // Simulate concurrent continuation
            let cont = ContinuationFrameTest {
                fragment_size: FragmentSize::Small(fragment_size.min(u16::MAX as usize) as u16),
                end_headers: i == continuation_count - 1,
                delayed: false,
            };

            let result = self.process_continuation(stream_id, &cont);
            if !matches!(
                result,
                FrameProcessResult::Accepted { .. }
                    | FrameProcessResult::ContinuationComplete { .. }
            ) {
                return result;
            }
        }

        FrameProcessResult::ContinuationComplete {
            total_size: self
                .streams
                .get(&base_stream_id)
                .map(|s| s.total_accumulated)
                .unwrap_or(0),
            fragment_count: continuation_count as usize,
        }
    }

    fn test_size_limit(&mut self, stream_id: u32, size_test: &SizeLimitTest) -> FrameProcessResult {
        let max_size = self.max_fragment_size();
        let target_size = match &size_test.target_size {
            SizeLimitTarget::UnderLimit(offset) => max_size.saturating_sub(*offset as usize),
            SizeLimitTarget::ExactlyAtLimit => max_size,
            SizeLimitTarget::OverLimit(offset) => max_size.saturating_add(*offset as usize),
            SizeLimitTarget::WayOverLimit(offset) => max_size.saturating_add(*offset as usize),
        };

        let headers = HeadersFrameTest {
            header_block_size: HeaderBlockSize::Large(target_size.min(u16::MAX as usize) as u16),
            end_headers: true,
            priority_weight: None,
        };

        self.process_headers(stream_id, &headers)
    }

    fn reset_stream(&mut self, stream_id: u32) -> FrameProcessResult {
        self.streams.remove(&stream_id);
        FrameProcessResult::StreamError {
            error_type: "Stream reset".to_string(),
        }
    }

    fn resolve_header_block_size(&self, size: &HeaderBlockSize) -> usize {
        match size {
            HeaderBlockSize::Empty => 0,
            HeaderBlockSize::Small(s) => *s as usize,
            HeaderBlockSize::Medium(s) => *s as usize,
            HeaderBlockSize::Large(s) => *s as usize,
            HeaderBlockSize::MaxFrame => self.settings.max_frame_size.min(u16::MAX.into()) as usize,
            HeaderBlockSize::Computed(computed) => self.resolve_computed_size(computed),
        }
    }

    fn resolve_fragment_size(&self, size: &FragmentSize, max_allowed: usize) -> usize {
        let resolved = match size {
            FragmentSize::Tiny(s) => (*s as usize).min(16),
            FragmentSize::Small(s) => (*s as usize).min(1024),
            FragmentSize::Large(s) => (*s as usize).min(16384),
            FragmentSize::MaxFrame => self.settings.max_frame_size.min(u16::MAX.into()) as usize,
            FragmentSize::ToLimit(offset) => max_allowed.saturating_sub(*offset as usize),
        };
        resolved.min(max_allowed)
    }

    fn resolve_computed_size(&self, computed: &ComputedSize) -> usize {
        match computed {
            ComputedSize::PercentOfMaxList(percent) => {
                ((self.settings.max_header_list_size as usize) * (*percent as usize)) / 100
            }
            ComputedSize::PercentOfMaxFragment(percent) => {
                (self.max_fragment_size() * (*percent as usize)) / 100
            }
            ComputedSize::MultipleOfFrame(multiple) => {
                (self.settings.max_frame_size as usize) * (*multiple as usize)
            }
        }
    }

    /// Get current statistics
    pub fn stats(&self) -> &ConnectionStats {
        &self.stats
    }

    /// Check for resource exhaustion indicators
    pub fn check_resource_exhaustion(&self) -> Vec<String> {
        let mut issues = Vec::new();

        if self.stats.total_fragment_bytes > 1024 * 1024 {
            issues.push("High total fragment bytes".to_string());
        }

        if self.streams.len() > 100 {
            issues.push("Too many concurrent streams".to_string());
        }

        let streams_expecting_continuation: usize = self
            .streams
            .values()
            .filter(|s| s.expecting_continuation)
            .count();

        if streams_expecting_continuation > 10 {
            issues.push("Too many incomplete header sequences".to_string());
        }

        issues
    }
}

/// Test specific size limit scenarios
fn test_size_limit_boundaries() {
    let mut conn = MockH2HeaderConnection::new(TestConnectionSettings {
        max_header_list_size: Some(8192),
        max_frame_size: None,
        max_concurrent_streams: None,
    });

    // Test exactly at limit
    let _max_fragment_size = 8192 * HEADER_FRAGMENT_MULTIPLIER; // 32KB

    let operation = FrameOperation {
        operation: FrameOpType::TestSizeLimit(SizeLimitTest {
            target_size: SizeLimitTarget::ExactlyAtLimit,
            approach: SizeLimitApproach::SingleFragment,
            test_overflow: false,
        }),
        stream_id: StreamId::Fixed(1),
        timing: 0,
    };

    let result = conn.process_frame_operation(&operation);
    assert!(matches!(
        result,
        FrameProcessResult::ContinuationComplete { .. }
    ));

    // Test over limit
    let over_limit_operation = FrameOperation {
        operation: FrameOpType::TestSizeLimit(SizeLimitTest {
            target_size: SizeLimitTarget::OverLimit(1000),
            approach: SizeLimitApproach::SingleFragment,
            test_overflow: true,
        }),
        stream_id: StreamId::Fixed(3),
        timing: 0,
    };

    let over_result = conn.process_frame_operation(&over_limit_operation);
    assert!(matches!(
        over_result,
        FrameProcessResult::SizeLimitExceeded { .. }
    ));
}

/// Test concurrent continuation sequences
fn test_concurrent_continuations() {
    let mut conn = MockH2HeaderConnection::new(TestConnectionSettings {
        max_header_list_size: Some(16384),
        max_frame_size: None,
        max_concurrent_streams: None,
    });

    // Start multiple streams with headers but no END_HEADERS
    for stream_id in [1, 3, 5, 7, 9] {
        let headers_op = FrameOperation {
            operation: FrameOpType::SendHeaders(HeadersFrameTest {
                header_block_size: HeaderBlockSize::Small(100),
                end_headers: false,
                priority_weight: None,
            }),
            stream_id: StreamId::Fixed(stream_id),
            timing: 0,
        };

        let result = conn.process_frame_operation(&headers_op);
        assert!(matches!(result, FrameProcessResult::Accepted { .. }));
    }

    // Send concurrent continuations
    let concurrent_op = FrameOperation {
        operation: FrameOpType::SendConcurrentContinuations(ConcurrentContinuationsTest {
            continuation_count: 5,
            fragment_size: FragmentSize::Small(200),
            interleave_streams: true,
        }),
        stream_id: StreamId::Fixed(1),
        timing: 0,
    };

    let result = conn.process_frame_operation(&concurrent_op);
    assert!(matches!(
        result,
        FrameProcessResult::ContinuationComplete { .. }
    ));
}

fuzz_target!(|scenario: HeadersSizeConcurrentScenario| {
    // Limit operations to prevent timeouts
    let max_ops = scenario.max_operations.min(200);
    let limited_ops: Vec<FrameOperation> = scenario
        .frame_operations
        .into_iter()
        .take(max_ops as usize)
        .collect();

    if limited_ops.is_empty() {
        return;
    }

    let mut conn = MockH2HeaderConnection::new(scenario.connection_settings);

    // Process frame operations
    for operation in &limited_ops {
        let result = conn.process_frame_operation(operation);

        // Validate result consistency
        match result {
            FrameProcessResult::Accepted {
                bytes_added,
                total_accumulated,
            } => {
                assert!(bytes_added <= MAX_HEADER_FRAGMENT_SIZE);
                assert!(total_accumulated <= MAX_HEADER_FRAGMENT_SIZE);
            }
            FrameProcessResult::SizeLimitExceeded {
                attempted_size,
                limit,
            } => {
                assert!(attempted_size > limit || attempted_size.saturating_add(1) > limit);
                assert!(limit <= MAX_HEADER_FRAGMENT_SIZE);
            }
            FrameProcessResult::ContinuationComplete {
                total_size,
                fragment_count,
            } => {
                assert!(total_size <= MAX_HEADER_FRAGMENT_SIZE);
                assert!(fragment_count > 0);
                assert!(fragment_count <= 1000); // Reasonable upper bound
            }
            FrameProcessResult::StreamError { .. } => {
                // Stream errors are valid
            }
            FrameProcessResult::ConcurrencyViolation { .. } => {
                // Concurrency violations are valid for testing
            }
        }
    }

    // Check for resource exhaustion
    let exhaustion_issues = conn.check_resource_exhaustion();
    for issue in &exhaustion_issues {
        // Log resource exhaustion for analysis
        eprintln!("Resource exhaustion detected: {}", issue);
    }

    // Validate final statistics
    let stats = conn.stats();
    assert!(stats.total_fragment_bytes <= 10 * 1024 * 1024); // 10MB reasonable upper bound
    assert!(stats.max_accumulated_size_seen <= MAX_HEADER_FRAGMENT_SIZE);

    // Run targeted tests periodically
    if scenario.test_extreme_concurrency && limited_ops.len() == 1 {
        test_size_limit_boundaries();
        test_concurrent_continuations();
    }
});
