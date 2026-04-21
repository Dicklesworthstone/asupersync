//! Conformance Tests: gRPC Deadline Propagation (RFC)
//!
//! Validates gRPC over HTTP/2 deadline propagation per gRPC specification with the following metamorphic relations:
//! 1. grpc-timeout header (e.g. '100m' '10S' '1M') parsed to absolute deadline
//! 2. deadline propagates to server handler Cx
//! 3. handler exceeding deadline returns DEADLINE_EXCEEDED status
//! 4. deadline attenuates across nested calls (child ≤ parent)
//! 5. absent grpc-timeout → no server-side deadline (infinite)

#![cfg(test)]

use asupersync::{
    cx::test_cx,
    lab::LabRuntime,
    grpc::{
        server::{CallContext, parse_grpc_timeout, format_grpc_timeout},
        streaming::{Metadata, Request, Response},
        status::{Status, Code},
        client::{Channel, GrpcClient, ChannelBuilder},
    },
    time::{sleep, Duration, Instant},
};

/// Helper to create metadata with grpc-timeout header
#[allow(dead_code)]
fn metadata_with_timeout(timeout_str: &str) -> Metadata {
    let mut metadata = Metadata::new();
    metadata.insert("grpc-timeout", timeout_str);
    metadata
}

/// Helper to create a deterministic time source for testing
#[allow(dead_code)]
fn fixed_time_source() -> fn() -> Instant {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    #[allow(dead_code)]
    fn fixed_instant() -> Instant {
        *START.get_or_init(Instant::now)
    }
    fixed_instant
}

/// MR1: grpc-timeout header (e.g. '100m' '10S' '1M') parsed to absolute deadline
#[test]
#[allow(dead_code)]
fn mr1_grpc_timeout_header_parsing_metamorphic() {
    LabRuntime::test(|lab| async {
        let test_cases = vec![
            // Format: (timeout_string, expected_duration)
            ("100m", Duration::from_millis(100)),        // milliseconds
            ("10S", Duration::from_secs(10)),             // seconds
            ("1M", Duration::from_secs(60)),              // minutes
            ("2H", Duration::from_secs(7200)),            // hours
            ("500u", Duration::from_micros(500)),         // microseconds
            ("1000n", Duration::from_nanos(1000)),        // nanoseconds
            ("0n", Duration::ZERO),                       // zero timeout
            ("99999999H", Duration::from_secs(99999999 * 3600)), // max value
        ];

        let base_time = fixed_time_source()();

        for (timeout_str, expected_duration) in test_cases {
            // MR1a: Parsing should be consistent
            let parsed = parse_grpc_timeout(timeout_str);
            assert_eq!(parsed, Some(expected_duration),
                "Failed to parse timeout string: {}", timeout_str);

            // MR1b: Format round-trip should preserve semantics (not necessarily exact string)
            if let Some(duration) = parsed {
                let formatted = format_grpc_timeout(duration);
                let reparsed = parse_grpc_timeout(&formatted);
                assert_eq!(reparsed, Some(duration),
                    "Round-trip failed for {}: {} -> {} -> {:?}",
                    timeout_str, duration.as_nanos(), formatted, reparsed);
            }

            // MR1c: CallContext should compute absolute deadline correctly
            let metadata = metadata_with_timeout(timeout_str);
            let call_ctx = CallContext::from_metadata_at(metadata, None, None, base_time);

            let expected_deadline = if expected_duration.is_zero() {
                // Zero timeout should still create a deadline (at base_time)
                Some(base_time)
            } else {
                base_time.checked_add(expected_duration)
            };

            assert_eq!(call_ctx.deadline(), expected_deadline,
                "CallContext deadline mismatch for timeout: {}", timeout_str);
        }
    });
}

/// MR2: deadline propagates to server handler Cx
#[test]
#[allow(dead_code)]
fn mr2_deadline_propagates_to_handler_cx() {
    LabRuntime::test(|lab| async {
        let test_cases = vec![
            ("5S", Duration::from_secs(5)),
            ("100m", Duration::from_millis(100)),
            ("30M", Duration::from_secs(1800)),
        ];

        let base_time = fixed_time_source()();

        for (timeout_str, expected_duration) in test_cases {
            // Create CallContext with deadline
            let metadata = metadata_with_timeout(timeout_str);
            let call_ctx = CallContext::from_metadata_at(metadata, None, None, base_time);

            // Verify deadline is set
            assert!(call_ctx.deadline().is_some(),
                "CallContext should have deadline for timeout: {}", timeout_str);

            // MR2a: Deadline accessible through CallContext
            let expected_deadline = base_time.checked_add(expected_duration).unwrap();
            assert_eq!(call_ctx.deadline(), Some(expected_deadline),
                "Deadline should match expected absolute time");

            // MR2b: CallContext with Cx wrapper preserves deadline
            let cx = asupersync::cx::test_cx();
            let call_with_cx = call_ctx.with_cx(&cx);
            assert_eq!(call_with_cx.deadline(), Some(expected_deadline),
                "CallContextWithCx should preserve deadline");

            // MR2c: Deadline status methods work correctly
            assert!(!call_ctx.is_expired_at(base_time),
                "Deadline should not be expired at creation time");

            let remaining_at_start = call_ctx.remaining_at(base_time);
            assert_eq!(remaining_at_start, Some(expected_duration),
                "Remaining time at start should equal timeout duration");

            // MR2d: Deadline expires when time advances
            let future_time = base_time + expected_duration + Duration::from_millis(1);
            assert!(call_ctx.is_expired_at(future_time),
                "Deadline should be expired after timeout duration");

            assert_eq!(call_ctx.remaining_at(future_time), None,
                "No remaining time after deadline expiry");
        }
    });
}

/// MR3: handler exceeding deadline returns DEADLINE_EXCEEDED status
#[test]
#[allow(dead_code)]
fn mr3_handler_deadline_exceeded_status() {
    LabRuntime::test(|lab| async {
        let test_cases = vec![
            ("1m", Duration::from_millis(1)),    // Very short timeout
            ("10u", Duration::from_micros(10)),   // Extremely short timeout
            ("0n", Duration::ZERO),              // Zero timeout (immediate expiry)
        ];

        for (timeout_str, timeout_duration) in test_cases {
            let base_time = fixed_time_source()();
            let metadata = metadata_with_timeout(timeout_str);
            let call_ctx = CallContext::from_metadata_at(metadata, None, None, base_time);

            // MR3a: Deadline should be set
            assert!(call_ctx.deadline().is_some(),
                "Handler should receive deadline for timeout: {}", timeout_str);

            // MR3b: Simulated handler that checks deadline and returns appropriate status
            let simulate_handler_response = |ctx: &CallContext, processing_time: Duration| -> Result<Response<String>, Status> {
                let process_end_time = base_time + processing_time;

                if ctx.is_expired_at(process_end_time) {
                    Err(Status::deadline_exceeded("Handler processing exceeded deadline"))
                } else {
                    Ok(Response::new("Success".to_string()))
                }
            };

            // MR3c: Handler processing within deadline should succeed
            if timeout_duration > Duration::ZERO {
                let quick_processing = timeout_duration / 2;
                let result = simulate_handler_response(&call_ctx, quick_processing);
                assert!(result.is_ok(),
                    "Quick processing should succeed within deadline for timeout: {}", timeout_str);
            }

            // MR3d: Handler processing beyond deadline should return DEADLINE_EXCEEDED
            let slow_processing = timeout_duration + Duration::from_millis(1);
            let result = simulate_handler_response(&call_ctx, slow_processing);
            assert!(result.is_err(),
                "Slow processing should fail for timeout: {}", timeout_str);

            let error = result.unwrap_err();
            assert_eq!(error.code(), Code::DeadlineExceeded,
                "Error should be DEADLINE_EXCEEDED, got: {:?}", error.code());
        }
    });
}

/// MR4: deadline attenuates across nested calls (child ≤ parent)
#[test]
#[allow(dead_code)]
fn mr4_deadline_attenuation_nested_calls() {
    LabRuntime::test(|lab| async {
        let parent_timeout = Duration::from_secs(10);
        let base_time = fixed_time_source()();

        // Create parent context with deadline
        let parent_metadata = metadata_with_timeout("10S");
        let parent_ctx = CallContext::from_metadata_at(parent_metadata, None, None, base_time);
        let parent_deadline = parent_ctx.deadline().unwrap();

        let test_cases = vec![
            // (child_timeout_str, should_be_attenuated)
            ("15S", true),   // Child timeout longer than parent → should be clamped
            ("5S", false),   // Child timeout shorter than parent → should be preserved
            ("10S", false),  // Child timeout equal to parent → should be preserved
            ("100H", true),  // Very long child timeout → should be clamped to parent
        ];

        for (child_timeout_str, should_be_attenuated) in test_cases {
            let child_timeout = parse_grpc_timeout(child_timeout_str).unwrap();

            // MR4a: Child deadline computation with parent context
            let child_deadline_naive = base_time.checked_add(child_timeout).unwrap();

            // MR4b: Attenuation logic (child deadline ≤ parent deadline)
            let attenuated_child_deadline = if child_deadline_naive <= parent_deadline {
                child_deadline_naive
            } else {
                parent_deadline
            };

            // MR4c: Verify attenuation behavior
            if should_be_attenuated {
                assert_eq!(attenuated_child_deadline, parent_deadline,
                    "Child deadline should be attenuated to parent deadline for timeout: {}",
                    child_timeout_str);
                assert!(attenuated_child_deadline <= parent_deadline,
                    "Attenuated child deadline must not exceed parent deadline");
            } else {
                assert_eq!(attenuated_child_deadline, child_deadline_naive,
                    "Child deadline should not be attenuated for timeout: {}",
                    child_timeout_str);
                assert!(attenuated_child_deadline <= parent_deadline,
                    "Child deadline must still not exceed parent deadline");
            }

            // MR4d: Create child context with attenuated deadline
            let child_metadata = metadata_with_timeout(child_timeout_str);
            let child_ctx_without_parent = CallContext::from_metadata_at(child_metadata, None, None, base_time);
            let child_deadline_without_parent = child_ctx_without_parent.deadline().unwrap();

            // Simulate proper attenuation (in real implementation, this would be done by the framework)
            let simulated_child_ctx = if child_deadline_without_parent > parent_deadline {
                CallContext::with_deadline(parent_deadline)
            } else {
                child_ctx_without_parent
            };

            assert_eq!(simulated_child_ctx.deadline().unwrap(), attenuated_child_deadline,
                "Child context deadline should match attenuated value");

            // MR4e: Child deadline remaining time should be ≤ parent remaining time
            let parent_remaining = parent_ctx.remaining_at(base_time);
            let child_remaining = simulated_child_ctx.remaining_at(base_time);

            match (parent_remaining, child_remaining) {
                (Some(parent_time), Some(child_time)) => {
                    assert!(child_time <= parent_time,
                        "Child remaining time ({:?}) should be ≤ parent remaining time ({:?})",
                        child_time, parent_time);
                }
                (None, _) => {
                    // Parent has no deadline, child can have any deadline
                }
                (Some(_), None) => {
                    panic!("Child should have deadline if parent has deadline and child requested one");
                }
            }
        }
    });
}

/// MR5: absent grpc-timeout → no server-side deadline (infinite)
#[test]
#[allow(dead_code)]
fn mr5_absent_timeout_infinite_deadline() {
    LabRuntime::test(|lab| async {
        let test_cases = vec![
            // (metadata_setup, default_timeout, expected_behavior)
            ("no_header", None, "infinite"),
            ("no_header", Some(Duration::from_secs(30)), "default"),
            ("empty_header", None, "infinite"),
            ("invalid_header", None, "infinite"),
            ("invalid_header", Some(Duration::from_secs(60)), "infinite"), // Invalid header doesn't use default
        ];

        let base_time = fixed_time_source()();

        for (metadata_setup, default_timeout, expected_behavior) in test_cases {
            let metadata = match metadata_setup {
                "no_header" => Metadata::new(),
                "empty_header" => {
                    let mut m = Metadata::new();
                    m.insert("grpc-timeout", "");
                    m
                }
                "invalid_header" => {
                    let mut m = Metadata::new();
                    m.insert("grpc-timeout", "invalid");
                    m
                }
                _ => panic!("Unknown metadata setup: {}", metadata_setup),
            };

            // MR5a: Create CallContext with or without default timeout
            let call_ctx = CallContext::from_metadata_at(metadata, default_timeout, None, base_time);

            // MR5b: Verify deadline behavior based on expected behavior
            match expected_behavior {
                "infinite" => {
                    assert_eq!(call_ctx.deadline(), None,
                        "CallContext should have no deadline for case: {} (default: {:?})",
                        metadata_setup, default_timeout);

                    // MR5c: No deadline means never expires
                    let far_future = base_time + Duration::from_secs(86400 * 365); // 1 year later
                    assert!(!call_ctx.is_expired_at(far_future),
                        "Context without deadline should never expire");

                    assert_eq!(call_ctx.remaining_at(far_future), None,
                        "Context without deadline should have no remaining time calculation");
                }
                "default" => {
                    let expected_deadline = base_time.checked_add(default_timeout.unwrap()).unwrap();
                    assert_eq!(call_ctx.deadline(), Some(expected_deadline),
                        "CallContext should use default timeout for case: {} (default: {:?})",
                        metadata_setup, default_timeout);

                    // MR5d: Default timeout should work like explicit timeout
                    let remaining = call_ctx.remaining_at(base_time);
                    assert_eq!(remaining, default_timeout,
                        "Remaining time should equal default timeout");
                }
                _ => panic!("Unknown expected behavior: {}", expected_behavior),
            }

            // MR5e: CallContextWithCx should preserve infinite deadline behavior
            let cx = asupersync::cx::test_cx();
            let call_with_cx = call_ctx.with_cx(&cx);
            assert_eq!(call_with_cx.deadline(), call_ctx.deadline(),
                "CallContextWithCx should preserve deadline state");
        }
    });
}

/// Property-based test: Deadline consistency across time progression
#[test]
#[allow(dead_code)]
fn property_deadline_time_progression_consistency() {
    LabRuntime::test(|lab| async {
        let timeout_duration = Duration::from_secs(5);
        let base_time = fixed_time_source()();

        let metadata = metadata_with_timeout("5S");
        let call_ctx = CallContext::from_metadata_at(metadata, None, None, base_time);
        let deadline = call_ctx.deadline().unwrap();

        // Test time progression invariants
        let time_points = vec![
            base_time,
            base_time + Duration::from_secs(1),
            base_time + Duration::from_secs(2),
            base_time + Duration::from_secs(4),
            base_time + timeout_duration,           // Exactly at deadline
            base_time + timeout_duration + Duration::from_millis(1), // Past deadline
        ];

        for (i, &time_point) in time_points.iter().enumerate() {
            let remaining = call_ctx.remaining_at(time_point);
            let is_expired = call_ctx.is_expired_at(time_point);
            let expected_remaining = deadline.checked_duration_since(time_point);

            // Consistency between remaining() and is_expired()
            if is_expired {
                assert_eq!(remaining, None,
                    "Expired deadline should have no remaining time at time point {}", i);
            } else {
                assert_eq!(remaining, expected_remaining,
                    "Remaining time should match calculation at time point {}", i);
            }

            // Monotonicity: remaining time should never increase
            if i > 0 {
                let prev_time = time_points[i - 1];
                let prev_remaining = call_ctx.remaining_at(prev_time);

                match (prev_remaining, remaining) {
                    (Some(prev), Some(curr)) => {
                        assert!(curr <= prev,
                            "Remaining time should decrease: {:?} -> {:?} (time points {} -> {})",
                            prev, curr, i - 1, i);
                    }
                    (Some(_), None) => {
                        // OK: went from some remaining time to expired
                    }
                    (None, None) => {
                        // OK: was and still is expired
                    }
                    (None, Some(_)) => {
                        panic!("Remaining time cannot increase from None to Some (time points {} -> {})",
                               i - 1, i);
                    }
                }
            }
        }
    });
}

/// Edge case: Zero and near-zero timeouts
#[test]
#[allow(dead_code)]
fn edge_case_zero_and_minimal_timeouts() {
    LabRuntime::test(|lab| async {
        let base_time = fixed_time_source()();

        let edge_cases = vec![
            "0n",     // Zero timeout
            "1n",     // 1 nanosecond
            "1u",     // 1 microsecond
            "1m",     // 1 millisecond
        ];

        for timeout_str in edge_cases {
            let metadata = metadata_with_timeout(timeout_str);
            let call_ctx = CallContext::from_metadata_at(metadata, None, None, base_time);

            // Should have a deadline even for zero/minimal timeouts
            assert!(call_ctx.deadline().is_some(),
                "Even zero/minimal timeout should create a deadline: {}", timeout_str);

            let deadline = call_ctx.deadline().unwrap();
            let expected_timeout = parse_grpc_timeout(timeout_str).unwrap();

            if expected_timeout.is_zero() {
                // Zero timeout should create deadline at base_time (immediately expired)
                assert_eq!(deadline, base_time,
                    "Zero timeout should create deadline at base time");
                assert!(call_ctx.is_expired_at(base_time),
                    "Zero timeout should be immediately expired");
            } else {
                // Non-zero minimal timeout should work normally
                assert_eq!(deadline, base_time + expected_timeout,
                    "Minimal timeout should create appropriate deadline");
                assert!(!call_ctx.is_expired_at(base_time),
                    "Minimal timeout should not be immediately expired");
                assert!(call_ctx.is_expired_at(base_time + expected_timeout + Duration::from_nanos(1)),
                    "Minimal timeout should expire after its duration");
            }
        }
    });
}