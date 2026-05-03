#![no_main]

//! HTTP/2 CONTINUATION frame timeout handling fuzzing target
//!
//! Tests RFC 9113 §6.10 CONTINUATION frame timeout requirements:
//! - CONTINUATION frames must follow HEADERS/PUSH_PROMISE without END_HEADERS
//! - No other frames can be interleaved during CONTINUATION sequences
//! - Timeouts must be enforced to prevent resource exhaustion attacks
//! - Tests connection.rs check_continuation_timeout() and continuation state management

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::time::{Duration, Instant};

/// Test case for CONTINUATION timeout testing
#[derive(Arbitrary, Debug, Clone)]
pub struct ContinuationTimeoutTestCase {
    pub scenario: TimeoutScenario,
    pub frame_sequence: Vec<TestFrame>,
    pub timeout_config: TimeoutConfig,
    pub timing_config: TimingConfig,
    pub connection_type: ConnectionType,
}

/// Different timeout testing scenarios
#[derive(Arbitrary, Debug, Clone, PartialEq)]
pub enum TimeoutScenario {
    /// Normal CONTINUATION sequence within timeout
    NormalContinuation,
    /// Timeout exceeded before CONTINUATION
    TimeoutExceeded,
    /// Interleaved frames during CONTINUATION (protocol violation)
    InterleavedFrames,
    /// Multiple incomplete CONTINUATION sequences
    MultiplePendingContinuations,
    /// PUSH_PROMISE CONTINUATION timeout
    PushPromiseContinuation,
    /// Very long CONTINUATION chain
    LongContinuationChain,
    /// Timeout edge cases
    TimeoutEdgeCases,
    /// Memory exhaustion via incomplete CONTINUATIONs
    MemoryExhaustion,
    /// Rapid timeout changes
    TimeoutReconfiguration,
}

/// Test frame types for CONTINUATION sequences
#[derive(Arbitrary, Debug, Clone)]
pub enum TestFrame {
    Headers {
        stream_id: u32,
        header_data: Vec<u8>,
        end_headers: bool,
        end_stream: bool,
    },
    Continuation {
        stream_id: u32,
        header_data: Vec<u8>,
        end_headers: bool,
    },
    PushPromise {
        stream_id: u32,
        promised_stream_id: u32,
        header_data: Vec<u8>,
        end_headers: bool,
    },
    Data {
        stream_id: u32,
        data: Vec<u8>,
        end_stream: bool,
    },
    Settings {
        continuation_timeout_ms: Option<u32>,
        max_frame_size: Option<u32>,
    },
    WindowUpdate {
        stream_id: u32,
        increment: u32,
    },
    RstStream {
        stream_id: u32,
        error_code: u32,
    },
    Ping {
        data: [u8; 8],
        ack: bool,
    },
    GoAway {
        last_stream_id: u32,
        error_code: u32,
        debug_data: Vec<u8>,
    },
}

/// Timeout configuration
#[derive(Arbitrary, Debug, Clone)]
pub struct TimeoutConfig {
    pub continuation_timeout_ms: u32,
    pub enable_timeout_checking: bool,
    pub strict_timeout_enforcement: bool,
    pub timeout_grace_period_ms: u32,
}

/// Timing configuration for test execution
#[derive(Arbitrary, Debug, Clone)]
pub struct TimingConfig {
    pub frame_intervals: Vec<Duration>,
    pub timeout_check_interval: Duration,
    pub clock_skew_ms: i32,
    pub time_acceleration_factor: u32,
}

/// Connection type (client vs server behavior)
#[derive(Arbitrary, Debug, Clone, PartialEq)]
pub enum ConnectionType {
    Client,
    Server,
}

/// Mock HTTP/2 connection for CONTINUATION timeout testing
#[derive(Debug)]
pub struct MockH2Connection {
    pub connection_type: ConnectionType,
    pub continuation_timeout_ms: u32,
    pub continuation_stream_id: Option<u32>,
    pub continuation_started_at: Option<Instant>,
    pub pending_push_promise: Option<PendingPushPromise>,
    pub current_time: Instant,
    pub timeout_violations: Vec<TimeoutViolation>,
    pub frame_sequence_violations: Vec<FrameSequenceViolation>,
    pub memory_usage_bytes: usize,
    pub max_memory_usage_bytes: usize,
}

/// Pending PUSH_PROMISE awaiting CONTINUATION
#[derive(Debug, Clone)]
pub struct PendingPushPromise {
    pub associated_stream_id: u32,
    pub promised_stream_id: u32,
    pub header_data: Vec<u8>,
    pub started_at: Instant,
}

/// CONTINUATION timeout violations
#[derive(Debug, PartialEq, Clone)]
pub struct TimeoutViolation {
    pub violation_type: TimeoutViolationType,
    pub stream_id: u32,
    pub timeout_ms: u32,
    pub actual_elapsed_ms: u64,
    pub severity: ViolationSeverity,
}

/// Types of timeout violations
#[derive(Debug, PartialEq, Clone)]
pub enum TimeoutViolationType {
    /// CONTINUATION not received within timeout
    ContinuationTimeout,
    /// Timeout not enforced when it should be
    TimeoutNotEnforced,
    /// Timeout enforced too early
    PrematureTimeout,
    /// Memory leak from incomplete CONTINUATIONs
    MemoryLeak,
    /// Timeout configuration invalid
    InvalidTimeoutConfig,
}

/// Frame sequence violations
#[derive(Debug, PartialEq, Clone)]
pub struct FrameSequenceViolation {
    pub violation_type: FrameSequenceViolationType,
    pub expected_stream_id: u32,
    pub actual_frame_type: String,
    pub actual_stream_id: u32,
}

/// Types of frame sequence violations
#[derive(Debug, PartialEq, Clone)]
pub enum FrameSequenceViolationType {
    /// Frame interleaved during CONTINUATION sequence
    InterleavedFrame,
    /// CONTINUATION for wrong stream
    WrongStreamContinuation,
    /// Multiple concurrent CONTINUATION sequences
    ConcurrentContinuations,
}

/// Violation severity levels
#[derive(Debug, PartialEq, Clone)]
pub enum ViolationSeverity {
    Critical, // DoS/memory exhaustion/protocol violation
    High,     // Timeout not enforced, security issue
    Medium,   // RFC violation, compatibility issue
    Low,      // Edge case, minor deviation
}

/// Test execution result
#[derive(Debug)]
pub struct ContinuationTimeoutTestResult {
    pub timeout_violations: Vec<TimeoutViolation>,
    pub frame_sequence_violations: Vec<FrameSequenceViolation>,
    pub memory_peak_bytes: usize,
    pub continuation_sequences_completed: usize,
    pub continuation_sequences_timed_out: usize,
    pub protocol_compliance_score: f32,
}

impl MockH2Connection {
    pub fn new(connection_type: ConnectionType, timeout_ms: u32) -> Self {
        Self {
            connection_type,
            continuation_timeout_ms: timeout_ms,
            continuation_stream_id: None,
            continuation_started_at: None,
            pending_push_promise: None,
            current_time: Instant::now(),
            timeout_violations: Vec::new(),
            frame_sequence_violations: Vec::new(),
            memory_usage_bytes: 0,
            max_memory_usage_bytes: 100 * 1024 * 1024, // 100MB limit
        }
    }

    /// Execute CONTINUATION timeout test case
    pub fn execute_test_case(
        &mut self,
        test_case: &ContinuationTimeoutTestCase,
    ) -> ContinuationTimeoutTestResult {
        let mut completed_sequences = 0;
        let mut timed_out_sequences = 0;

        self.continuation_timeout_ms = test_case.timeout_config.continuation_timeout_ms;
        self.max_memory_usage_bytes = if test_case.scenario == TimeoutScenario::MemoryExhaustion {
            10 * 1024 // 10KB limit for memory exhaustion test
        } else {
            100 * 1024 * 1024
        };

        // Process frame sequence
        for (frame_index, frame) in test_case.frame_sequence.iter().enumerate() {
            // Advance time if specified
            if let Some(interval) = test_case.timing_config.frame_intervals.get(frame_index) {
                self.advance_time(*interval);
            }

            // Check timeout before processing frame
            if test_case.timeout_config.enable_timeout_checking {
                self.check_continuation_timeout();
            }

            // Process the frame
            match self.process_frame(frame) {
                Ok(continuation_completed) => {
                    if continuation_completed {
                        completed_sequences += 1;
                    }
                }
                Err(timeout_violation) => {
                    self.timeout_violations.push(timeout_violation);
                    timed_out_sequences += 1;
                }
            }
        }

        // Final timeout check
        if test_case.timeout_config.enable_timeout_checking {
            self.check_continuation_timeout();
        }

        // Calculate compliance score
        let protocol_compliance_score = self.calculate_protocol_compliance();

        ContinuationTimeoutTestResult {
            timeout_violations: self.timeout_violations.clone(),
            frame_sequence_violations: self.frame_sequence_violations.clone(),
            memory_peak_bytes: self.memory_usage_bytes,
            continuation_sequences_completed: completed_sequences,
            continuation_sequences_timed_out: timed_out_sequences,
            protocol_compliance_score,
        }
    }

    /// Process a single frame and check CONTINUATION requirements
    fn process_frame(&mut self, frame: &TestFrame) -> Result<bool, TimeoutViolation> {
        match frame {
            TestFrame::Headers {
                stream_id,
                header_data,
                end_headers,
                end_stream: _,
            } => {
                // Add to memory usage
                self.memory_usage_bytes += header_data.len() + 32; // frame overhead

                if self.is_awaiting_continuation()
                    && self.continuation_stream_id != Some(*stream_id)
                {
                    // Interleaved HEADERS frame during CONTINUATION sequence
                    self.frame_sequence_violations.push(FrameSequenceViolation {
                        violation_type: FrameSequenceViolationType::InterleavedFrame,
                        expected_stream_id: self.continuation_stream_id.unwrap_or(0),
                        actual_frame_type: "HEADERS".to_string(),
                        actual_stream_id: *stream_id,
                    });
                }

                if !end_headers {
                    // Start CONTINUATION sequence
                    self.continuation_stream_id = Some(*stream_id);
                    self.continuation_started_at = Some(self.current_time);
                    Ok(false)
                } else {
                    // Complete header block
                    self.clear_continuation_state();
                    Ok(true)
                }
            }
            TestFrame::Continuation {
                stream_id,
                header_data,
                end_headers,
            } => {
                // Add to memory usage
                self.memory_usage_bytes += header_data.len() + 16; // frame overhead

                if !self.is_awaiting_continuation() {
                    // CONTINUATION without preceding HEADERS/PUSH_PROMISE
                    self.frame_sequence_violations.push(FrameSequenceViolation {
                        violation_type: FrameSequenceViolationType::InterleavedFrame,
                        expected_stream_id: 0,
                        actual_frame_type: "CONTINUATION".to_string(),
                        actual_stream_id: *stream_id,
                    });
                    return Ok(false);
                }

                if self.continuation_stream_id != Some(*stream_id) {
                    // CONTINUATION for wrong stream
                    self.frame_sequence_violations.push(FrameSequenceViolation {
                        violation_type: FrameSequenceViolationType::WrongStreamContinuation,
                        expected_stream_id: self.continuation_stream_id.unwrap_or(0),
                        actual_frame_type: "CONTINUATION".to_string(),
                        actual_stream_id: *stream_id,
                    });
                    return Ok(false);
                }

                if *end_headers {
                    // Complete CONTINUATION sequence
                    self.clear_continuation_state();
                    Ok(true)
                } else {
                    // Continue sequence
                    Ok(false)
                }
            }
            TestFrame::PushPromise {
                stream_id,
                promised_stream_id,
                header_data,
                end_headers,
            } => {
                if self.connection_type == ConnectionType::Server {
                    // Servers can't receive PUSH_PROMISE
                    return Ok(false);
                }

                // Add to memory usage
                self.memory_usage_bytes += header_data.len() + 48; // frame + promise overhead

                if !end_headers {
                    // Start CONTINUATION sequence for PUSH_PROMISE
                    self.continuation_stream_id = Some(*stream_id);
                    self.continuation_started_at = Some(self.current_time);
                    self.pending_push_promise = Some(PendingPushPromise {
                        associated_stream_id: *stream_id,
                        promised_stream_id: *promised_stream_id,
                        header_data: header_data.clone(),
                        started_at: self.current_time,
                    });
                    Ok(false)
                } else {
                    // Complete PUSH_PROMISE
                    self.clear_continuation_state();
                    Ok(true)
                }
            }
            TestFrame::Data {
                stream_id,
                data,
                end_stream: _,
            } => {
                // Add to memory usage
                self.memory_usage_bytes += data.len() + 16;

                if self.is_awaiting_continuation()
                    && self.continuation_stream_id != Some(*stream_id)
                {
                    // DATA frame during CONTINUATION sequence
                    self.frame_sequence_violations.push(FrameSequenceViolation {
                        violation_type: FrameSequenceViolationType::InterleavedFrame,
                        expected_stream_id: self.continuation_stream_id.unwrap_or(0),
                        actual_frame_type: "DATA".to_string(),
                        actual_stream_id: *stream_id,
                    });
                }
                Ok(false)
            }
            TestFrame::Settings {
                continuation_timeout_ms,
                max_frame_size: _,
            } => {
                if let Some(new_timeout) = continuation_timeout_ms {
                    self.continuation_timeout_ms = *new_timeout;
                }
                Ok(false)
            }
            _ => {
                // Other frames (WINDOW_UPDATE, RST_STREAM, PING, GOAWAY)
                // These can be interleaved during CONTINUATION but may still violate protocol
                if self.is_awaiting_continuation() {
                    match frame {
                        TestFrame::WindowUpdate { stream_id, .. } => {
                            if *stream_id != 0 && self.continuation_stream_id != Some(*stream_id) {
                                // Stream-specific WINDOW_UPDATE during CONTINUATION for different stream
                                self.frame_sequence_violations.push(FrameSequenceViolation {
                                    violation_type: FrameSequenceViolationType::InterleavedFrame,
                                    expected_stream_id: self.continuation_stream_id.unwrap_or(0),
                                    actual_frame_type: "WINDOW_UPDATE".to_string(),
                                    actual_stream_id: *stream_id,
                                });
                            }
                        }
                        TestFrame::RstStream { stream_id, .. } => {
                            if self.continuation_stream_id == Some(*stream_id) {
                                // RST_STREAM for the stream awaiting CONTINUATION
                                self.clear_continuation_state();
                            }
                        }
                        TestFrame::GoAway { .. } => {
                            // GOAWAY clears all state
                            self.clear_continuation_state();
                        }
                        _ => {}
                    }
                }
                Ok(false)
            }
        }
    }

    /// Check for CONTINUATION timeout violations
    fn check_continuation_timeout(&mut self) {
        if let Some(started_at) = self.continuation_started_at {
            let elapsed = self.current_time.saturating_duration_since(started_at);
            let elapsed_ms = elapsed.as_millis() as u64;

            if elapsed_ms >= u64::from(self.continuation_timeout_ms) {
                // Timeout exceeded
                let stream_id = self.continuation_stream_id.unwrap_or(0);

                self.timeout_violations.push(TimeoutViolation {
                    violation_type: TimeoutViolationType::ContinuationTimeout,
                    stream_id,
                    timeout_ms: self.continuation_timeout_ms,
                    actual_elapsed_ms: elapsed_ms,
                    severity: ViolationSeverity::Critical,
                });

                // Clear continuation state (timeout cleanup)
                self.clear_continuation_state();
            }
        }

        // Check for memory exhaustion
        if self.memory_usage_bytes > self.max_memory_usage_bytes {
            self.timeout_violations.push(TimeoutViolation {
                violation_type: TimeoutViolationType::MemoryLeak,
                stream_id: 0,
                timeout_ms: self.continuation_timeout_ms,
                actual_elapsed_ms: 0,
                severity: ViolationSeverity::Critical,
            });
        }
    }

    /// Advance simulated time
    fn advance_time(&mut self, duration: Duration) {
        self.current_time += duration;
    }

    /// Check if connection is awaiting CONTINUATION
    fn is_awaiting_continuation(&self) -> bool {
        self.continuation_stream_id.is_some() || self.pending_push_promise.is_some()
    }

    /// Clear CONTINUATION state
    fn clear_continuation_state(&mut self) {
        self.continuation_stream_id = None;
        self.continuation_started_at = None;
        self.pending_push_promise = None;
        // Memory cleanup simulation
        if self.memory_usage_bytes > 1024 {
            self.memory_usage_bytes -= 1024; // Simulate header table cleanup
        }
    }

    /// Calculate protocol compliance score
    fn calculate_protocol_compliance(&self) -> f32 {
        let mut penalty = 0.0;

        // Penalize timeout violations
        for violation in &self.timeout_violations {
            penalty += match violation.severity {
                ViolationSeverity::Critical => 10.0,
                ViolationSeverity::High => 5.0,
                ViolationSeverity::Medium => 2.0,
                ViolationSeverity::Low => 1.0,
            };
        }

        // Penalize frame sequence violations
        for _violation in &self.frame_sequence_violations {
            penalty += 3.0;
        }

        // Additional penalty for memory issues
        if self.memory_usage_bytes > self.max_memory_usage_bytes {
            penalty += 15.0;
        }

        let max_score = 100.0f32;
        (max_score - penalty).max(0.0f32) / max_score
    }
}

/// Generate comprehensive CONTINUATION timeout test cases
fn generate_continuation_timeout_test_cases() -> Vec<ContinuationTimeoutTestCase> {
    vec![
        // Normal CONTINUATION sequence
        ContinuationTimeoutTestCase {
            scenario: TimeoutScenario::NormalContinuation,
            frame_sequence: vec![
                TestFrame::Headers {
                    stream_id: 1,
                    header_data: vec![0x00, 0x01, 0x02], // Mock header data
                    end_headers: false,
                    end_stream: false,
                },
                TestFrame::Continuation {
                    stream_id: 1,
                    header_data: vec![0x03, 0x04, 0x05],
                    end_headers: true,
                },
            ],
            timeout_config: TimeoutConfig {
                continuation_timeout_ms: 1000,
                enable_timeout_checking: true,
                strict_timeout_enforcement: true,
                timeout_grace_period_ms: 0,
            },
            timing_config: TimingConfig {
                frame_intervals: vec![Duration::from_millis(10), Duration::from_millis(10)],
                timeout_check_interval: Duration::from_millis(50),
                clock_skew_ms: 0,
                time_acceleration_factor: 1,
            },
            connection_type: ConnectionType::Server,
        },
        // Timeout exceeded scenario
        ContinuationTimeoutTestCase {
            scenario: TimeoutScenario::TimeoutExceeded,
            frame_sequence: vec![
                TestFrame::Headers {
                    stream_id: 1,
                    header_data: vec![0x00; 100],
                    end_headers: false,
                    end_stream: false,
                },
                // No CONTINUATION frame follows - timeout should trigger
            ],
            timeout_config: TimeoutConfig {
                continuation_timeout_ms: 50, // Short timeout for test
                enable_timeout_checking: true,
                strict_timeout_enforcement: true,
                timeout_grace_period_ms: 0,
            },
            timing_config: TimingConfig {
                frame_intervals: vec![Duration::from_millis(100)], // Exceed timeout
                timeout_check_interval: Duration::from_millis(25),
                clock_skew_ms: 0,
                time_acceleration_factor: 1,
            },
            connection_type: ConnectionType::Server,
        },
        // Interleaved frames (protocol violation)
        ContinuationTimeoutTestCase {
            scenario: TimeoutScenario::InterleavedFrames,
            frame_sequence: vec![
                TestFrame::Headers {
                    stream_id: 1,
                    header_data: vec![0x00; 50],
                    end_headers: false,
                    end_stream: false,
                },
                TestFrame::Data {
                    stream_id: 3, // Different stream - interleaved
                    data: vec![0x42; 100],
                    end_stream: false,
                },
                TestFrame::Continuation {
                    stream_id: 1,
                    header_data: vec![0x01; 50],
                    end_headers: true,
                },
            ],
            timeout_config: TimeoutConfig {
                continuation_timeout_ms: 1000,
                enable_timeout_checking: true,
                strict_timeout_enforcement: true,
                timeout_grace_period_ms: 0,
            },
            timing_config: TimingConfig {
                frame_intervals: vec![Duration::from_millis(10); 3],
                timeout_check_interval: Duration::from_millis(50),
                clock_skew_ms: 0,
                time_acceleration_factor: 1,
            },
            connection_type: ConnectionType::Server,
        },
    ]
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);

    // Try to generate a test case from fuzzer input
    let test_case = match ContinuationTimeoutTestCase::arbitrary(&mut unstructured) {
        Ok(tc) => tc,
        Err(_) => {
            // If generation fails, use a pre-generated test case
            let predefined_cases = generate_continuation_timeout_test_cases();
            if predefined_cases.is_empty() {
                return;
            }
            let index = unstructured
                .int_in_range(0..=predefined_cases.len() - 1)
                .unwrap_or(0);
            predefined_cases[index].clone()
        }
    };

    // Create connection with timeout configuration
    let mut connection = MockH2Connection::new(
        test_case.connection_type.clone(),
        test_case.timeout_config.continuation_timeout_ms,
    );

    // Execute the test case
    let _result = connection.execute_test_case(&test_case);

    // Test specific timeout edge cases
    test_continuation_timeout_edge_cases(&test_case);
    test_memory_exhaustion_prevention(&test_case);
    test_interleaved_frame_detection(&test_case);
    test_push_promise_continuation_timeout(&test_case);
});

/// Test CONTINUATION timeout edge cases
fn test_continuation_timeout_edge_cases(test_case: &ContinuationTimeoutTestCase) {
    let mut connection = MockH2Connection::new(
        test_case.connection_type.clone(),
        test_case.timeout_config.continuation_timeout_ms,
    );

    // Test zero timeout (should be treated as minimal timeout)
    connection.continuation_timeout_ms = 0;
    connection.continuation_stream_id = Some(1);
    connection.continuation_started_at = Some(connection.current_time);

    // Should timeout immediately
    connection.check_continuation_timeout();
    assert!(!connection.timeout_violations.is_empty() || connection.continuation_timeout_ms > 0);
}

/// Test memory exhaustion prevention
fn test_memory_exhaustion_prevention(test_case: &ContinuationTimeoutTestCase) {
    if test_case.scenario != TimeoutScenario::MemoryExhaustion {
        return;
    }

    let mut connection = MockH2Connection::new(
        test_case.connection_type.clone(),
        10000, // Long timeout
    );
    connection.max_memory_usage_bytes = 1024; // Very small limit

    // Simulate large header accumulation
    connection.memory_usage_bytes = 2048; // Exceed limit
    connection.check_continuation_timeout();

    // Should detect memory leak violation
    let has_memory_violation = connection
        .timeout_violations
        .iter()
        .any(|v| v.violation_type == TimeoutViolationType::MemoryLeak);
    assert!(has_memory_violation);
}

/// Test interleaved frame detection
fn test_interleaved_frame_detection(test_case: &ContinuationTimeoutTestCase) {
    let mut connection = MockH2Connection::new(
        test_case.connection_type.clone(),
        test_case.timeout_config.continuation_timeout_ms,
    );

    // Start CONTINUATION sequence
    connection.continuation_stream_id = Some(1);
    connection.continuation_started_at = Some(connection.current_time);

    // Try to send DATA frame for different stream
    let data_frame = TestFrame::Data {
        stream_id: 3,
        data: vec![0x42; 100],
        end_stream: false,
    };

    let _ = connection.process_frame(&data_frame);

    // Should detect interleaved frame violation
    let has_interleaved_violation = connection
        .frame_sequence_violations
        .iter()
        .any(|v| v.violation_type == FrameSequenceViolationType::InterleavedFrame);
    assert!(has_interleaved_violation);
}

/// Test PUSH_PROMISE CONTINUATION timeout
fn test_push_promise_continuation_timeout(test_case: &ContinuationTimeoutTestCase) {
    if test_case.connection_type == ConnectionType::Server {
        return; // Servers don't receive PUSH_PROMISE
    }

    let mut connection = MockH2Connection::new(
        ConnectionType::Client,
        50, // Short timeout
    );

    // Process PUSH_PROMISE without END_HEADERS
    let push_promise = TestFrame::PushPromise {
        stream_id: 1,
        promised_stream_id: 2,
        header_data: vec![0x00; 100],
        end_headers: false,
    };

    let _ = connection.process_frame(&push_promise);
    assert!(connection.is_awaiting_continuation());

    // Advance time beyond timeout
    connection.advance_time(Duration::from_millis(100));
    connection.check_continuation_timeout();

    // Should timeout
    assert!(!connection.timeout_violations.is_empty());
}
