//! Error Message Golden Artifacts ([br-golden-5])
//!
//! Golden tests for error message bytes to ensure consistent error formatting
//! across panic recovery, supervision restart logs, and region close cause chains.
//! These goldens validate that error messages remain stable for debugging and
//! monitoring purposes.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;

    /// Error message golden test infrastructure
    struct ErrorGoldenTester {
        name: String,
        golden_dir: String,
    }

    impl ErrorGoldenTester {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                golden_dir: "tests/golden/errors".to_string(),
            }
        }

        /// Assert error message bytes match golden with UPDATE_GOLDENS support
        fn assert_error_golden(&self, test_name: &str, error_bytes: &[u8]) {
            let golden_path =
                Path::new(&self.golden_dir).join(format!("{}.{}.golden", self.name, test_name));

            if std::env::var("UPDATE_GOLDENS").is_ok() {
                fs::create_dir_all(golden_path.parent().unwrap()).unwrap();
                fs::write(&golden_path, error_bytes).unwrap();
                eprintln!("[GOLDEN] Updated: {}", golden_path.display());
                return;
            }

            let expected = fs::read(&golden_path).unwrap_or_else(|_| {
                panic!(
                    "Error golden missing: {}\nRun with UPDATE_GOLDENS=1 to create",
                    golden_path.display()
                )
            });

            if error_bytes != expected {
                let actual_path = golden_path.with_extension("actual");
                fs::write(&actual_path, error_bytes).unwrap();

                panic!(
                    "ERROR GOLDEN MISMATCH: {}.{}\n\
                     Expected {} bytes, got {} bytes\n\
                     To update: UPDATE_GOLDENS=1 cargo test\n\
                     To diff: diff {} {}",
                    self.name,
                    test_name,
                    expected.len(),
                    error_bytes.len(),
                    golden_path.display(),
                    actual_path.display()
                );
            }
        }
    }

    // Mock error types for consistent error message generation

    #[derive(Debug)]
    struct MockPanicInfo {
        message: String,
        location: String,
        thread_name: String,
    }

    #[derive(Debug)]
    struct MockSupervisionEvent {
        actor_id: String,
        restart_count: u32,
        failure_reason: String,
        restart_strategy: String,
    }

    #[derive(Debug)]
    struct MockRegionCloseEvent {
        region_id: String,
        cause_chain: Vec<String>,
        obligations_leaked: u32,
        cleanup_budget_used: u64,
    }

    // Error message formatters

    fn format_panic_recovery(panic: &MockPanicInfo) -> Vec<u8> {
        format!(
            "PANIC_RECOVERY[{}]: {} at {}\n\
             Stack trace suppressed for deterministic testing.\n\
             Recovery: isolate panic, drain region, finalize obligations.",
            panic.thread_name, panic.message, panic.location
        )
        .into_bytes()
    }

    fn format_supervision_restart(event: &MockSupervisionEvent) -> Vec<u8> {
        format!(
            "SUPERVISION_RESTART[{}]: restart #{} due to '{}'\n\
             Strategy: {}\n\
             Action: spawn replacement, transfer state, resume supervision.",
            event.actor_id, event.restart_count, event.failure_reason, event.restart_strategy
        )
        .into_bytes()
    }

    fn format_region_close_cause_chain(event: &MockRegionCloseEvent) -> Vec<u8> {
        let mut output = format!(
            "REGION_CLOSE[{}]: {} obligations leaked, {} cleanup budget used\n\
             Cause chain ({} entries):\n",
            event.region_id,
            event.obligations_leaked,
            event.cleanup_budget_used,
            event.cause_chain.len()
        );

        for (i, cause) in event.cause_chain.iter().enumerate() {
            output.push_str(&format!("  {}: {}\n", i + 1, cause));
        }

        output.push_str("Finalization: all obligations resolved, region quiesced.");
        output.into_bytes()
    }

    // Golden tests

    #[test]
    fn test_panic_recovery_task_spawn_overflow() {
        let tester = ErrorGoldenTester::new("panic_recovery");

        let panic = MockPanicInfo {
            message: "task spawn overflow: region capacity exceeded".to_string(),
            location: "src/runtime/region_table.rs:425:13".to_string(),
            thread_name: "asupersync-worker-3".to_string(),
        };

        let error_bytes = format_panic_recovery(&panic);
        tester.assert_error_golden("task_spawn_overflow", &error_bytes);
    }

    #[test]
    fn test_panic_recovery_obligation_leak() {
        let tester = ErrorGoldenTester::new("panic_recovery");

        let panic = MockPanicInfo {
            message: "obligation leak detected: 7 unresolved tokens".to_string(),
            location: "src/obligation/ledger.rs:892:17".to_string(),
            thread_name: "asupersync-supervisor".to_string(),
        };

        let error_bytes = format_panic_recovery(&panic);
        tester.assert_error_golden("obligation_leak", &error_bytes);
    }

    #[test]
    fn test_panic_recovery_channel_bounds_violation() {
        let tester = ErrorGoldenTester::new("panic_recovery");

        let panic = MockPanicInfo {
            message: "mpsc channel bounds violation: 16384 > 8192 limit".to_string(),
            location: "src/channel/mpsc.rs:234:9".to_string(),
            thread_name: "asupersync-io-driver".to_string(),
        };

        let error_bytes = format_panic_recovery(&panic);
        tester.assert_error_golden("channel_bounds_violation", &error_bytes);
    }

    #[test]
    fn test_supervision_restart_gen_server_crash() {
        let tester = ErrorGoldenTester::new("supervision_restart");

        let event = MockSupervisionEvent {
            actor_id: "kafka_consumer_actor_partition_7".to_string(),
            restart_count: 3,
            failure_reason: "broker connection lost: TCP RST received".to_string(),
            restart_strategy: "exponential_backoff(initial=100ms, max=30s)".to_string(),
        };

        let error_bytes = format_supervision_restart(&event);
        tester.assert_error_golden("gen_server_crash", &error_bytes);
    }

    #[test]
    fn test_supervision_restart_raptorq_decoder_stall() {
        let tester = ErrorGoldenTester::new("supervision_restart");

        let event = MockSupervisionEvent {
            actor_id: "raptorq_decoder_stream_42".to_string(),
            restart_count: 1,
            failure_reason: "decode stall: insufficient symbols after 30s timeout".to_string(),
            restart_strategy: "immediate_restart_with_state_transfer".to_string(),
        };

        let error_bytes = format_supervision_restart(&event);
        tester.assert_error_golden("raptorq_decoder_stall", &error_bytes);
    }

    #[test]
    fn test_supervision_restart_obligation_tracker_deadlock() {
        let tester = ErrorGoldenTester::new("supervision_restart");

        let event = MockSupervisionEvent {
            actor_id: "obligation_tracker_region_allocator".to_string(),
            restart_count: 0,
            failure_reason: "deadlock detected: circular dependency in token resolution"
                .to_string(),
            restart_strategy: "kill_and_restart_with_fresh_state".to_string(),
        };

        let error_bytes = format_supervision_restart(&event);
        tester.assert_error_golden("obligation_tracker_deadlock", &error_bytes);
    }

    #[test]
    fn test_region_close_clean_shutdown() {
        let tester = ErrorGoldenTester::new("region_close");

        let event = MockRegionCloseEvent {
            region_id: "app_server_main_region".to_string(),
            cause_chain: vec![
                "SIGTERM received from process supervisor".to_string(),
                "graceful_shutdown() initiated with 30s timeout".to_string(),
                "all HTTP connections drained successfully".to_string(),
                "database connection pool closed cleanly".to_string(),
            ],
            obligations_leaked: 0,
            cleanup_budget_used: 250,
        };

        let error_bytes = format_region_close_cause_chain(&event);
        tester.assert_error_golden("clean_shutdown", &error_bytes);
    }

    #[test]
    fn test_region_close_forced_shutdown_with_leaks() {
        let tester = ErrorGoldenTester::new("region_close");

        let event = MockRegionCloseEvent {
            region_id: "websocket_handler_region_8".to_string(),
            cause_chain: vec![
                "client connection lost: TCP FIN received".to_string(),
                "cleanup timeout: 5s budget exhausted".to_string(),
                "force close initiated: 2 obligations abandoned".to_string(),
                "obligation finalizer ran emergency drain".to_string(),
            ],
            obligations_leaked: 2,
            cleanup_budget_used: 5000,
        };

        let error_bytes = format_region_close_cause_chain(&event);
        tester.assert_error_golden("forced_shutdown_with_leaks", &error_bytes);
    }

    #[test]
    fn test_region_close_cascade_failure() {
        let tester = ErrorGoldenTester::new("region_close");

        let event = MockRegionCloseEvent {
            region_id: "distributed_consensus_coordinator".to_string(),
            cause_chain: vec![
                "quorum lost: 3/5 nodes unreachable".to_string(),
                "leadership election timeout after 10s".to_string(),
                "consensus state machine stalled".to_string(),
                "supervision strategy: fail_fast_cascade".to_string(),
                "parent region triggered emergency close".to_string(),
                "spillover: 17 child regions also closed".to_string(),
            ],
            obligations_leaked: 5,
            cleanup_budget_used: 12000,
        };

        let error_bytes = format_region_close_cause_chain(&event);
        tester.assert_error_golden("cascade_failure", &error_bytes);
    }

    #[test]
    fn test_region_close_resource_exhaustion() {
        let tester = ErrorGoldenTester::new("region_close");

        let event = MockRegionCloseEvent {
            region_id: "file_upload_processor_batch_worker".to_string(),
            cause_chain: vec![
                "memory pressure: heap allocation failed".to_string(),
                "back-pressure activated: input queue full".to_string(),
                "emergency shedding: 128 pending uploads dropped".to_string(),
            ],
            obligations_leaked: 0,
            cleanup_budget_used: 800,
        };

        let error_bytes = format_region_close_cause_chain(&event);
        tester.assert_error_golden("resource_exhaustion", &error_bytes);
    }

    // Cross-cutting error scenarios

    #[test]
    fn test_combined_panic_and_supervision_cascade() {
        let tester = ErrorGoldenTester::new("combined_errors");

        // Panic leads to supervision restart which triggers region close
        let panic_bytes = format_panic_recovery(&MockPanicInfo {
            message: "arithmetic overflow in obligation counter".to_string(),
            location: "src/obligation/graded.rs:156:21".to_string(),
            thread_name: "asupersync-obligation-worker".to_string(),
        });

        let supervision_bytes = format_supervision_restart(&MockSupervisionEvent {
            actor_id: "obligation_graded_counter_actor".to_string(),
            restart_count: 5,
            failure_reason: "max restart threshold exceeded (5/5)".to_string(),
            restart_strategy: "escalate_to_parent_supervision_tree".to_string(),
        });

        let region_bytes = format_region_close_cause_chain(&MockRegionCloseEvent {
            region_id: "obligation_management_subsystem".to_string(),
            cause_chain: vec![
                "child supervision escalation received".to_string(),
                "subsystem health check failed".to_string(),
                "coordinated shutdown initiated".to_string(),
            ],
            obligations_leaked: 1,
            cleanup_budget_used: 3000,
        });

        let combined_bytes = [
            panic_bytes,
            b"\n---\n".to_vec(),
            supervision_bytes,
            b"\n---\n".to_vec(),
            region_bytes,
        ]
        .concat();

        tester.assert_error_golden("panic_supervision_cascade", &combined_bytes);
    }

    #[test]
    fn test_distributed_system_partition_recovery() {
        let tester = ErrorGoldenTester::new("distributed_errors");

        // Network partition causes multiple coordinated region closes
        let mut partition_events = Vec::new();

        for node_id in 1..=3 {
            let event = MockRegionCloseEvent {
                region_id: format!("consensus_node_{}", node_id),
                cause_chain: vec![
                    format!(
                        "network partition detected: lost contact with {} peers",
                        4 - node_id
                    ),
                    "split-brain prevention: minority partition shutdown".to_string(),
                    "state preserved for partition healing".to_string(),
                ],
                obligations_leaked: 0,
                cleanup_budget_used: 1500,
            };
            partition_events.push(format_region_close_cause_chain(&event));
        }

        // `.as_slice()` coerces the byte literal `&[u8; 5]` to `&[u8]` so
        // `Vec<Vec<u8>>::join` accepts it as a separator slice.
        let combined = partition_events.join(b"\n===\n".as_slice());
        tester.assert_error_golden("distributed_partition", &combined);
    }
}
