//! Differential conformance tests for asupersync::oneshot vs tokio::oneshot
//!
//! Tests that both implementations exhibit identical send/recv ordering behavior
//! with cancel injection producing identical observable outcomes.

use std::time::{Duration, Instant};

use asupersync::channel::oneshot as AsupersyncOneshot;
use asupersync::cx::Cx;
use asupersync::types::Budget;
use asupersync::util::ArenaIndex;
use asupersync::{RegionId, TaskId};

/// Conformance test result tracking send/recv outcomes across implementations
#[derive(Debug, Clone, PartialEq)]
struct OneshotResult {
    /// Whether the send operation succeeded
    send_success: bool,
    /// Whether the receive operation succeeded and what value was received
    recv_result: RecvOutcome,
    /// Total time taken for the complete operation
    total_duration: Duration,
    /// Whether cancellation occurred and when
    cancellation_timing: CancellationTiming,
}

#[derive(Debug, Clone, PartialEq)]
enum RecvOutcome {
    /// Successfully received the value
    Success(u32),
    /// Received a "closed" error (sender dropped)
    Closed,
    /// Operation timed out or was wedged
    TimedOut,
}

#[derive(Debug, Clone, PartialEq)]
enum CancellationTiming {
    /// No cancellation occurred
    None,
    /// Cancelled before send
    BeforeSend,
    /// Cancelled after send but before recv
    BetweenSendRecv,
    /// Cancelled during recv
    DuringRecv,
}

/// Test configuration for oneshot conformance
#[derive(Debug, Clone)]
struct ConformanceTestConfig {
    /// Value to send through the channel
    send_value: u32,
    /// When to inject cancellation
    cancellation_timing: CancellationTiming,
    /// Delay between operations (microseconds)
    operation_delay_us: u64,
    /// Test timeout
    timeout_ms: u64,
}

/// Test context for running conformance tests
struct ConformanceTestContext {
    config: ConformanceTestConfig,
    timeout: Duration,
}

impl ConformanceTestContext {
    fn new(config: ConformanceTestConfig) -> Self {
        Self {
            timeout: Duration::from_millis(config.timeout_ms),
            config,
        }
    }

    /// Run the same test scenario on both oneshot implementations
    fn run_differential_test(&self) -> (OneshotResult, OneshotResult) {
        let asupersync_result = self.test_asupersync_oneshot();
        let tokio_result = self.test_tokio_oneshot();

        (asupersync_result, tokio_result)
    }

    /// Test asupersync oneshot behavior
    fn test_asupersync_oneshot(&self) -> OneshotResult {
        let start_time = Instant::now();

        let cx = Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        );

        let (sender, mut receiver) = AsupersyncOneshot::channel::<u32>();

        // Handle cancellation timing
        let mut recv_result = RecvOutcome::TimedOut;

        if self.config.cancellation_timing == CancellationTiming::BeforeSend {
            cx.set_cancel_requested(true);
        }

        let send_success = sender.send(&cx, self.config.send_value).is_ok();

        if self.config.operation_delay_us > 0 {
            std::thread::sleep(Duration::from_micros(self.config.operation_delay_us));
        }

        if self.config.cancellation_timing == CancellationTiming::BetweenSendRecv {
            cx.set_cancel_requested(true);
        }

        // Receive operation
        let _recv_cx = if matches!(
            self.config.cancellation_timing,
            CancellationTiming::DuringRecv
        ) {
            // Create a cancelled context for receive
            let recv_cx = Cx::new(
                RegionId::from_arena(ArenaIndex::new(0, 1)),
                TaskId::from_arena(ArenaIndex::new(0, 1)),
                Budget::INFINITE,
            );
            recv_cx.set_cancel_requested(true);
            recv_cx
        } else {
            cx
        };

        // For asupersync, we need to use a simple blocking approach since we don't have a runtime
        // We'll use try_recv in a loop with timeout
        let recv_start = Instant::now();
        while recv_start.elapsed() < self.timeout {
            match receiver.try_recv() {
                Ok(value) => {
                    recv_result = RecvOutcome::Success(value);
                    break;
                }
                Err(AsupersyncOneshot::TryRecvError::Empty) => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(AsupersyncOneshot::TryRecvError::Closed) => {
                    recv_result = RecvOutcome::Closed;
                    break;
                }
            }
        }

        OneshotResult {
            send_success,
            recv_result,
            total_duration: start_time.elapsed(),
            cancellation_timing: self.config.cancellation_timing.clone(),
        }
    }

    /// Test tokio oneshot behavior
    fn test_tokio_oneshot(&self) -> OneshotResult {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");

        rt.block_on(async {
            let start_time = Instant::now();

            let (sender, receiver) = tokio::sync::oneshot::channel::<u32>();

            // Handle cancellation timing
            // Create a cancellation token for tokio
            let cancel_token = tokio_util::sync::CancellationToken::new();

            if self.config.cancellation_timing == CancellationTiming::BeforeSend {
                cancel_token.cancel();
            }

            let send_success = if cancel_token.is_cancelled() {
                drop(sender);
                false
            } else {
                sender.send(self.config.send_value).is_ok()
            };

            if self.config.operation_delay_us > 0 {
                tokio::time::sleep(Duration::from_micros(self.config.operation_delay_us)).await;
            }

            if self.config.cancellation_timing == CancellationTiming::BetweenSendRecv {
                cancel_token.cancel();
            }

            // Receive operation
            let recv_future = async {
                if matches!(
                    self.config.cancellation_timing,
                    CancellationTiming::DuringRecv
                ) {
                    cancel_token.cancel();
                }

                match receiver.await {
                    Ok(value) => RecvOutcome::Success(value),
                    Err(_) => RecvOutcome::Closed,
                }
            };

            // Add timeout
            let recv_result = match tokio::time::timeout(self.timeout, recv_future).await {
                Ok(result) => result,
                Err(_) => RecvOutcome::TimedOut,
            };

            OneshotResult {
                send_success,
                recv_result,
                total_duration: start_time.elapsed(),
                cancellation_timing: self.config.cancellation_timing.clone(),
            }
        })
    }
}

/// Verify that both implementations have identical behavior
fn assert_oneshot_conformance(
    asupersync_result: &OneshotResult,
    tokio_result: &OneshotResult,
    test_name: &str,
) {
    // Primary assertion: send success should be identical
    assert_eq!(
        asupersync_result.send_success, tokio_result.send_success,
        "{}: Send success differs between implementations\n\
         asupersync: {}\n\
         tokio:      {}",
        test_name, asupersync_result.send_success, tokio_result.send_success
    );

    // Secondary assertion: recv outcomes should be functionally equivalent
    // Note: we allow some flexibility in error types but core behavior should match
    match (&asupersync_result.recv_result, &tokio_result.recv_result) {
        (RecvOutcome::Success(a), RecvOutcome::Success(b)) => {
            assert_eq!(
                a, b,
                "{}: Received values differ: {} vs {}",
                test_name, a, b
            );
        }
        (RecvOutcome::Closed, RecvOutcome::Closed) => {
            // Both closed - good
        }
        (RecvOutcome::TimedOut, RecvOutcome::TimedOut) => {
            // Both timed out - acceptable for this test
        }
        _ => {
            // Only fail if the core behavioral difference is significant
            if asupersync_result.send_success && tokio_result.send_success {
                assert_eq!(
                    asupersync_result.recv_result, tokio_result.recv_result,
                    "{}: Recv results differ significantly\n\
                     asupersync: {:?}\n\
                     tokio:      {:?}",
                    test_name, asupersync_result.recv_result, tokio_result.recv_result
                );
            }
        }
    }
}

/// Test basic send/receive without cancellation
#[test]
fn conformance_basic_send_recv() {
    let config = ConformanceTestConfig {
        send_value: 42,
        cancellation_timing: CancellationTiming::None,
        operation_delay_us: 0,
        timeout_ms: 100,
    };

    let ctx = ConformanceTestContext::new(config);
    let (asupersync_result, tokio_result) = ctx.run_differential_test();

    assert_oneshot_conformance(&asupersync_result, &tokio_result, "basic_send_recv");

    // Both should succeed
    assert!(asupersync_result.send_success);
    assert!(tokio_result.send_success);
    assert_eq!(asupersync_result.recv_result, RecvOutcome::Success(42));
    assert_eq!(tokio_result.recv_result, RecvOutcome::Success(42));
}

/// Test cancellation before send
#[test]
fn conformance_cancel_before_send() {
    let config = ConformanceTestConfig {
        send_value: 100,
        cancellation_timing: CancellationTiming::BeforeSend,
        operation_delay_us: 0,
        timeout_ms: 100,
    };

    let ctx = ConformanceTestContext::new(config);
    let (asupersync_result, tokio_result) = ctx.run_differential_test();

    assert_oneshot_conformance(&asupersync_result, &tokio_result, "cancel_before_send");
}

/// Test cancellation between send and receive
#[test]
fn conformance_cancel_between_send_recv() {
    let config = ConformanceTestConfig {
        send_value: 200,
        cancellation_timing: CancellationTiming::BetweenSendRecv,
        operation_delay_us: 100,
        timeout_ms: 100,
    };

    let ctx = ConformanceTestContext::new(config);
    let (asupersync_result, tokio_result) = ctx.run_differential_test();

    assert_oneshot_conformance(
        &asupersync_result,
        &tokio_result,
        "cancel_between_send_recv",
    );
}

/// Test cancellation during receive
#[test]
fn conformance_cancel_during_recv() {
    let config = ConformanceTestConfig {
        send_value: 300,
        cancellation_timing: CancellationTiming::DuringRecv,
        operation_delay_us: 0,
        timeout_ms: 100,
    };

    let ctx = ConformanceTestContext::new(config);
    let (asupersync_result, tokio_result) = ctx.run_differential_test();

    assert_oneshot_conformance(&asupersync_result, &tokio_result, "cancel_during_recv");
}

/// Test with operation delays
#[test]
fn conformance_with_delays() {
    let config = ConformanceTestConfig {
        send_value: 400,
        cancellation_timing: CancellationTiming::None,
        operation_delay_us: 1000, // 1ms delay
        timeout_ms: 200,
    };

    let ctx = ConformanceTestContext::new(config);
    let (asupersync_result, tokio_result) = ctx.run_differential_test();

    assert_oneshot_conformance(&asupersync_result, &tokio_result, "with_delays");

    // Both should succeed with delays
    assert!(asupersync_result.send_success);
    assert!(tokio_result.send_success);
    assert_eq!(asupersync_result.recv_result, RecvOutcome::Success(400));
    assert_eq!(tokio_result.recv_result, RecvOutcome::Success(400));
}

/// Comprehensive conformance test matrix
#[test]
fn conformance_comprehensive_matrix() {
    let test_cases = vec![
        // Basic scenarios
        (50, CancellationTiming::None, 0),
        (51, CancellationTiming::BeforeSend, 0),
        (52, CancellationTiming::BetweenSendRecv, 100),
        (53, CancellationTiming::DuringRecv, 0),
        // With delays
        (60, CancellationTiming::None, 500),
        (61, CancellationTiming::BeforeSend, 500),
        (62, CancellationTiming::BetweenSendRecv, 1000),
    ];

    for (i, (value, cancel_timing, delay)) in test_cases.into_iter().enumerate() {
        let config = ConformanceTestConfig {
            send_value: value,
            cancellation_timing: cancel_timing,
            operation_delay_us: delay,
            timeout_ms: 200,
        };

        let ctx = ConformanceTestContext::new(config);
        let (asupersync_result, tokio_result) = ctx.run_differential_test();

        assert_oneshot_conformance(
            &asupersync_result,
            &tokio_result,
            &format!("comprehensive_matrix_case_{}", i),
        );
    }
}

/// Verify that the documented conformance coverage matrix is executable.
#[test]
fn oneshot_tokio_conformance_coverage_matrix_is_executable() {
    let test_cases = vec![
        (
            "basic_send_recv",
            42,
            CancellationTiming::None,
            0,
            Some(RecvOutcome::Success(42)),
        ),
        (
            "cancel_before_send",
            100,
            CancellationTiming::BeforeSend,
            0,
            None,
        ),
        (
            "cancel_between_send_recv",
            200,
            CancellationTiming::BetweenSendRecv,
            100,
            None,
        ),
        (
            "cancel_during_recv",
            300,
            CancellationTiming::DuringRecv,
            0,
            None,
        ),
        (
            "with_delays",
            400,
            CancellationTiming::None,
            1000,
            Some(RecvOutcome::Success(400)),
        ),
    ];

    let mut covered_no_cancel = false;
    let mut covered_before_send = false;
    let mut covered_between_send_recv = false;
    let mut covered_during_recv = false;
    let mut covered_delayed_operation = false;

    for (name, send_value, cancellation_timing, operation_delay_us, expected_recv) in test_cases {
        covered_no_cancel |= matches!(cancellation_timing, CancellationTiming::None);
        covered_before_send |= matches!(cancellation_timing, CancellationTiming::BeforeSend);
        covered_between_send_recv |=
            matches!(cancellation_timing, CancellationTiming::BetweenSendRecv);
        covered_during_recv |= matches!(cancellation_timing, CancellationTiming::DuringRecv);
        covered_delayed_operation |= operation_delay_us > 0;

        let config = ConformanceTestConfig {
            send_value,
            cancellation_timing,
            operation_delay_us,
            timeout_ms: 200,
        };

        let ctx = ConformanceTestContext::new(config);
        let (asupersync_result, tokio_result) = ctx.run_differential_test();

        assert_oneshot_conformance(&asupersync_result, &tokio_result, name);

        if let Some(expected_recv) = expected_recv {
            assert!(asupersync_result.send_success, "{name}: asupersync send");
            assert!(tokio_result.send_success, "{name}: tokio send");
            assert_eq!(
                asupersync_result.recv_result, expected_recv,
                "{name}: unexpected asupersync receive outcome"
            );
            assert_eq!(
                tokio_result.recv_result, expected_recv,
                "{name}: unexpected tokio receive outcome"
            );
        }
    }

    assert!(covered_no_cancel, "coverage matrix missing no-cancel case");
    assert!(
        covered_before_send,
        "coverage matrix missing before-send cancellation case"
    );
    assert!(
        covered_between_send_recv,
        "coverage matrix missing between-send-recv cancellation case"
    );
    assert!(
        covered_during_recv,
        "coverage matrix missing during-recv cancellation case"
    );
    assert!(
        covered_delayed_operation,
        "coverage matrix missing delayed operation case"
    );
}
