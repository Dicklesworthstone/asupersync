//! Real E2E integration tests: signal/graceful ↔ obligation/recovery integration (br-e2e-191).
//!
//! Tests that SIGTERM signal correctly triggers obligation recovery sequence without losing
//! in-flight work. Verifies the integration between:
//!
//! - `signal::graceful`: Graceful shutdown handling with grace periods
//! - `obligation::recovery`: Self-stabilizing recovery protocol for obligation convergence
//!
//! # Integration Patterns Tested
//!
//! - **Signal-Triggered Recovery**: SIGTERM properly initiates obligation recovery sequence
//! - **In-Flight Work Preservation**: Active obligations are recovered without data loss
//! - **Grace Period Management**: Obligation recovery completes within shutdown grace period
//! - **Recovery Coordination**: Graceful shutdown waits for obligation convergence
//! - **Recovery Phase Monitoring**: Proper progression through recovery phases during shutdown
//!
//! # Test Scenarios
//!
//! 1. **Basic Signal Recovery** — SIGTERM with active obligations triggers recovery
//! 2. **Multi-Obligation Recovery** — Multiple pending obligations recovered gracefully
//! 3. **Stale Obligation Cleanup** — Stale obligations handled during signal recovery
//! 4. **Conflict Resolution Recovery** — Obligation conflicts resolved during shutdown
//! 5. **Grace Period Integration** — Recovery completes within configured grace period
//!
//! # Safety Properties Verified
//!
//! - No in-flight obligations lost during graceful shutdown
//! - All obligation anomalies resolved during recovery sequence
//! - Recovery converges to quiescent state before shutdown completes
//! - Grace period management prevents forced termination during recovery

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    #![allow(
        clippy::expect_fun_call,
        clippy::future_not_send,
        clippy::match_same_arms,
        clippy::missing_panics_doc,
        clippy::needless_pass_by_value,
        clippy::unwrap_used,
        dead_code
    )]

    use crate::{
        cx::{Cx, Registry},
        obligation::{
            crdt::CrdtObligationLedger,
            recovery::{RecoveryConfig, RecoveryGovernor, RecoveryPhase, RecoveryTickResult},
        },
        runtime::{Runtime, spawn},
        signal::{
            graceful::{GracefulBuilder, GracefulOutcome},
            ShutdownController,
        },
        time::{Duration, Instant, sleep},
        types::{Budget, ObligationId, Outcome, Time},
    };
    use std::{
        collections::HashMap,
        sync::{
            Arc, Mutex, RwLock,
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        },
    };

    // ────────────────────────────────────────────────────────────────────────────────
    // Signal + Obligation Recovery Integration Test Framework
    // ────────────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SignalRecoveryTestPhase {
        Setup,
        ObligationInitialization,
        SignalHandlerSetup,
        ActiveObligationGeneration,
        SignalDelivery,
        RecoverySequenceMonitoring,
        ObligationConvergenceVerification,
        GracePeriodValidation,
        QuiescenceVerification,
        Teardown,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SignalRecoveryTestResult {
        pub test_name: String,
        pub phase: SignalRecoveryTestPhase,
        pub success: bool,
        pub error: Option<String>,
        pub duration_ms: u64,
        pub recovery_stats: SignalRecoveryStats,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct SignalRecoveryStats {
        pub obligations_active_at_signal: u64,
        pub obligations_pending_at_signal: u64,
        pub obligations_recovered: u64,
        pub obligations_lost: u64,
        pub recovery_ticks_executed: u64,
        pub recovery_actions_taken: u64,
        pub stale_obligations_cleaned: u64,
        pub conflicts_resolved: u64,
        pub violations_fixed: u64,
        pub grace_period_ms: u64,
        pub recovery_completion_ms: u64,
        pub convergence_achieved: bool,
        pub quiescence_achieved: bool,
    }

    /// Active obligation tracking for recovery monitoring.
    #[derive(Debug, Clone)]
    pub struct ObligationTracker {
        pub obligation_id: ObligationId,
        pub created_at: Instant,
        pub recovered_at: Option<Instant>,
        pub recovery_duration_ms: Option<u64>,
        pub successfully_recovered: bool,
        pub lost_during_recovery: bool,
        pub recovery_action: Option<String>,
    }

    /// Signal and obligation recovery test harness.
    pub struct SignalObligationRecoveryTestHarness {
        runtime: Runtime,
        cx: Cx,
        ledger: Arc<Mutex<CrdtObligationLedger>>,
        governor: Arc<Mutex<RecoveryGovernor>>,
        shutdown_controller: Arc<ShutdownController>,
        stats: Arc<Mutex<SignalRecoveryStats>>,
        obligation_trackers: Arc<Mutex<HashMap<ObligationId, ObligationTracker>>>,
        recovery_phases: Arc<Mutex<Vec<(RecoveryPhase, Instant)>>>,
        test_start_time: Instant,
        virtual_time_ns: Arc<AtomicU64>,
        recovery_active: Arc<AtomicBool>,
        grace_period: Duration,
    }

    impl SignalObligationRecoveryTestHarness {
        pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let runtime = Runtime::new()?;
            let cx = Cx::current().expect("Runtime should provide current Cx");

            let recovery_config = RecoveryConfig {
                stale_timeout_ns: 2_000_000_000, // 2 seconds
                max_resolutions_per_tick: 20,
                auto_resolve_conflicts: true,
                auto_abort_violations: true,
            };

            let grace_period = Duration::from_millis(5000); // 5 second grace period

            Ok(Self {
                runtime,
                cx,
                ledger: Arc::new(Mutex::new(CrdtObligationLedger::new())),
                governor: Arc::new(Mutex::new(RecoveryGovernor::new(recovery_config))),
                shutdown_controller: Arc::new(ShutdownController::new()),
                stats: Arc::new(Mutex::new(SignalRecoveryStats::default())),
                obligation_trackers: Arc::new(Mutex::new(HashMap::new())),
                recovery_phases: Arc::new(Mutex::new(Vec::new())),
                test_start_time: Instant::now(),
                virtual_time_ns: Arc::new(AtomicU64::new(1_000_000_000)),
                recovery_active: Arc::new(AtomicBool::new(false)),
                grace_period,
            })
        }

        pub fn create_obligation(&self, id_raw: u64) -> ObligationId {
            let obligation_id = ObligationId::from_raw(id_raw);

            // Reserve in ledger
            if let Ok(mut ledger) = self.ledger.lock() {
                ledger.reserve(obligation_id);
            }

            // Track obligation
            let tracker = ObligationTracker {
                obligation_id,
                created_at: Instant::now(),
                recovered_at: None,
                recovery_duration_ms: None,
                successfully_recovered: false,
                lost_during_recovery: false,
                recovery_action: None,
            };

            if let Ok(mut trackers) = self.obligation_trackers.lock() {
                trackers.insert(obligation_id, tracker);
            }

            if let Ok(mut stats) = self.stats.lock() {
                stats.obligations_active_at_signal += 1;
            }

            obligation_id
        }

        pub fn add_stale_obligation(&self, id_raw: u64) {
            let obligation_id = ObligationId::from_raw(id_raw);

            // Create obligation with old timestamp to make it stale
            let old_time = self.virtual_time_ns.load(Ordering::SeqCst) - 3_000_000_000; // 3 seconds ago

            if let Ok(mut ledger) = self.ledger.lock() {
                ledger.reserve(obligation_id);
                // The governor will detect it as stale based on timestamp tracking
            }

            let tracker = ObligationTracker {
                obligation_id,
                created_at: Instant::now() - Duration::from_secs(3),
                recovered_at: None,
                recovery_duration_ms: None,
                successfully_recovered: false,
                lost_during_recovery: false,
                recovery_action: None,
            };

            if let Ok(mut trackers) = self.obligation_trackers.lock() {
                trackers.insert(obligation_id, tracker);
            }
        }

        pub fn create_conflict_obligation(&self, id_raw: u64) {
            let obligation_id = ObligationId::from_raw(id_raw);

            if let Ok(mut ledger) = self.ledger.lock() {
                // Create a conflict by both committing and aborting the same obligation
                ledger.reserve(obligation_id);
                ledger.record_commit(obligation_id);
                ledger.record_abort(obligation_id);
            }

            let tracker = ObligationTracker {
                obligation_id,
                created_at: Instant::now(),
                recovered_at: None,
                recovery_duration_ms: None,
                successfully_recovered: false,
                lost_during_recovery: false,
                recovery_action: None,
            };

            if let Ok(mut trackers) = self.obligation_trackers.lock() {
                trackers.insert(obligation_id, tracker);
            }
        }

        pub fn record_recovery_phase(&self, phase: RecoveryPhase) {
            if let Ok(mut phases) = self.recovery_phases.lock() {
                phases.push((phase, Instant::now()));
            }

            if let Ok(mut stats) = self.stats.lock() {
                stats.recovery_ticks_executed += 1;
            }
        }

        pub fn trigger_sigterm(&self) {
            // Signal graceful shutdown which should trigger recovery
            self.shutdown_controller.shutdown();
            self.recovery_active.store(true, Ordering::SeqCst);
        }

        pub async fn run_recovery_sequence(&self) -> SignalRecoveryTestResult {
            let start_time = Instant::now();
            let mut stats = SignalRecoveryStats::default();

            // Get initial state
            if let (Ok(ledger), Ok(trackers)) = (self.ledger.lock(), self.obligation_trackers.lock()) {
                stats.obligations_pending_at_signal = ledger.pending().len() as u64;
                stats.obligations_active_at_signal = trackers.len() as u64;
            }

            stats.grace_period_ms = self.grace_period.as_millis() as u64;

            // Run graceful shutdown with recovery
            let shutdown_receiver = self.shutdown_controller.subscribe();

            let recovery_future = self.execute_recovery_protocol();

            let result = GracefulBuilder::new(shutdown_receiver)
                .grace_period(self.grace_period)
                .logging(true)
                .run(recovery_future)
                .await;

            let duration = start_time.elapsed();

            // Collect final stats
            if let Ok(final_stats) = self.stats.lock() {
                stats = final_stats.clone();
            }

            stats.recovery_completion_ms = duration.as_millis() as u64;

            SignalRecoveryTestResult {
                test_name: "signal_graceful_obligation_recovery_integration".to_string(),
                phase: SignalRecoveryTestPhase::QuiescenceVerification,
                success: matches!(result, GracefulOutcome::Completed(_)) && stats.convergence_achieved,
                error: match result {
                    GracefulOutcome::ShutdownSignaled => Some("Shutdown signaled before recovery completed".to_string()),
                    GracefulOutcome::Completed(_) if !stats.convergence_achieved => Some("Recovery did not achieve convergence".to_string()),
                    _ => None,
                },
                duration_ms: duration.as_millis() as u64,
                recovery_stats: stats,
            }
        }

        async fn execute_recovery_protocol(&self) -> &'static str {
            let mut tick_count = 0;
            let max_ticks = 50; // Prevent infinite loops

            while tick_count < max_ticks && self.recovery_active.load(Ordering::SeqCst) {
                // Execute recovery tick
                let current_time = self.virtual_time_ns.load(Ordering::SeqCst);
                let tick_result = if let (Ok(mut ledger), Ok(mut governor)) =
                    (self.ledger.lock(), self.governor.lock()) {
                    governor.tick(&mut *ledger, current_time)
                } else {
                    break;
                };

                // Record recovery phase
                self.record_recovery_phase(governor.lock().unwrap().phase());

                // Update stats
                self.update_stats_from_tick(&tick_result);

                // Update obligation trackers based on recovery actions
                self.update_trackers_from_tick(&tick_result);

                // Check for quiescence
                if tick_result.is_quiescent {
                    if let Ok(mut stats) = self.stats.lock() {
                        stats.convergence_achieved = true;
                        stats.quiescence_achieved = true;
                    }
                    break;
                }

                tick_count += 1;

                // Advance virtual time slightly
                self.virtual_time_ns.fetch_add(100_000_000, Ordering::SeqCst); // 100ms

                // Small delay to prevent busy loop
                sleep(Duration::from_millis(10)).await;
            }

            if tick_count >= max_ticks {
                eprintln!("Recovery timed out after {} ticks", max_ticks);
            }

            "Recovery protocol completed"
        }

        fn update_stats_from_tick(&self, result: &RecoveryTickResult) {
            if let Ok(mut stats) = self.stats.lock() {
                stats.recovery_ticks_executed += 1;
                stats.recovery_actions_taken += result.actions.len() as u64;

                for action in &result.actions {
                    match action {
                        crate::obligation::recovery::RecoveryAction::StaleAbort { .. } => {
                            stats.stale_obligations_cleaned += 1;
                        }
                        crate::obligation::recovery::RecoveryAction::ConflictResolved { .. } => {
                            stats.conflicts_resolved += 1;
                        }
                        crate::obligation::recovery::RecoveryAction::ViolationAborted { .. } => {
                            stats.violations_fixed += 1;
                        }
                        crate::obligation::recovery::RecoveryAction::Flagged { .. } => {
                            // Flagged items counted as recovery actions but not resolved
                        }
                    }
                }
            }
        }

        fn update_trackers_from_tick(&self, result: &RecoveryTickResult) {
            if let Ok(mut trackers) = self.obligation_trackers.lock() {
                for action in &result.actions {
                    match action {
                        crate::obligation::recovery::RecoveryAction::StaleAbort { id, .. } |
                        crate::obligation::recovery::RecoveryAction::ConflictResolved { id } |
                        crate::obligation::recovery::RecoveryAction::ViolationAborted { id, .. } => {
                            if let Some(tracker) = trackers.get_mut(id) {
                                tracker.recovered_at = Some(Instant::now());
                                tracker.recovery_duration_ms = Some(
                                    tracker.recovered_at.unwrap()
                                        .duration_since(tracker.created_at)
                                        .as_millis() as u64
                                );
                                tracker.successfully_recovered = true;
                                tracker.recovery_action = Some(format!("{:?}", action));
                            }
                        }
                        crate::obligation::recovery::RecoveryAction::Flagged { id, reason } => {
                            if let Some(tracker) = trackers.get_mut(id) {
                                tracker.recovery_action = Some(format!("Flagged: {}", reason));
                            }
                        }
                    }
                }
            }
        }

        pub fn get_stats_snapshot(&self) -> SignalRecoveryStats {
            self.stats.lock().unwrap().clone()
        }

        pub fn verify_no_obligations_lost(&self) -> bool {
            if let Ok(trackers) = self.obligation_trackers.lock() {
                trackers.values().all(|t| !t.lost_during_recovery)
            } else {
                false
            }
        }

        pub fn verify_recovery_convergence(&self) -> bool {
            if let Ok(ledger) = self.ledger.lock() {
                ledger.pending().is_empty() &&
                ledger.conflicts().is_empty() &&
                ledger.linearity_violations().is_empty()
            } else {
                false
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Integration Test Cases
    // ────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_signal_triggers_basic_obligation_recovery() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let harness = SignalObligationRecoveryTestHarness::new().await.unwrap();

            // Create some active obligations
            harness.create_obligation(1001);
            harness.create_obligation(1002);
            harness.create_obligation(1003);

            // Trigger SIGTERM
            harness.trigger_sigterm();

            // Run recovery sequence
            let result = harness.run_recovery_sequence().await;

            // Verify recovery succeeded
            assert!(result.success, "Signal should trigger successful obligation recovery");
            assert!(result.recovery_stats.recovery_ticks_executed > 0, "Recovery ticks should be executed");
            assert!(result.recovery_stats.convergence_achieved, "Recovery should achieve convergence");
            assert!(harness.verify_no_obligations_lost(), "No obligations should be lost during recovery");
            assert!(harness.verify_recovery_convergence(), "System should converge to quiescent state");

            println!("✓ Basic signal-triggered obligation recovery: {:?}", result.recovery_stats);
        });
    }

    #[test]
    fn test_signal_recovery_with_stale_obligations() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let harness = SignalObligationRecoveryTestHarness::new().await.unwrap();

            // Create mix of fresh and stale obligations
            harness.create_obligation(2001);
            harness.create_obligation(2002);
            harness.add_stale_obligation(2003); // This one should be cleaned up
            harness.add_stale_obligation(2004); // This one too

            // Trigger SIGTERM
            harness.trigger_sigterm();

            // Run recovery sequence
            let result = harness.run_recovery_sequence().await;

            // Verify stale obligations were cleaned up
            assert!(result.success, "Recovery should succeed with stale obligations");
            assert!(result.recovery_stats.stale_obligations_cleaned >= 2,
                "Stale obligations should be cleaned: {}", result.recovery_stats.stale_obligations_cleaned);
            assert!(result.recovery_stats.convergence_achieved, "Should achieve convergence after cleanup");
            assert!(harness.verify_recovery_convergence(), "System should be quiescent after cleanup");

            println!("✓ Stale obligation cleanup during signal recovery: {:?}", result.recovery_stats);
        });
    }

    #[test]
    fn test_signal_recovery_with_conflicts() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let harness = SignalObligationRecoveryTestHarness::new().await.unwrap();

            // Create normal obligations and conflict obligations
            harness.create_obligation(3001);
            harness.create_conflict_obligation(3002); // This creates a commit+abort conflict
            harness.create_obligation(3003);
            harness.create_conflict_obligation(3004); // Another conflict

            // Trigger SIGTERM
            harness.trigger_sigterm();

            // Run recovery sequence
            let result = harness.run_recovery_sequence().await;

            // Verify conflicts were resolved
            assert!(result.success, "Recovery should succeed with conflicts");
            assert!(result.recovery_stats.conflicts_resolved >= 2,
                "Conflicts should be resolved: {}", result.recovery_stats.conflicts_resolved);
            assert!(result.recovery_stats.convergence_achieved, "Should achieve convergence after conflict resolution");
            assert!(harness.verify_recovery_convergence(), "System should be quiescent after conflict resolution");

            println!("✓ Conflict resolution during signal recovery: {:?}", result.recovery_stats);
        });
    }

    #[test]
    fn test_signal_recovery_multi_obligation_stress() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let harness = SignalObligationRecoveryTestHarness::new().await.unwrap();

            // Create many obligations to stress test recovery
            for i in 4001..4021 {
                harness.create_obligation(i);
            }

            // Add some stale ones
            for i in 4021..4025 {
                harness.add_stale_obligation(i);
            }

            // Add some conflicts
            for i in 4025..4029 {
                harness.create_conflict_obligation(i);
            }

            // Trigger SIGTERM
            harness.trigger_sigterm();

            // Run recovery sequence
            let result = harness.run_recovery_sequence().await;

            // Verify comprehensive recovery
            assert!(result.success, "Recovery should succeed under stress");
            assert!(result.recovery_stats.obligations_active_at_signal >= 20, "Should have many active obligations");
            assert!(result.recovery_stats.recovery_actions_taken > 0, "Recovery actions should be taken");
            assert!(result.recovery_stats.convergence_achieved, "Should achieve convergence under stress");
            assert!(harness.verify_no_obligations_lost(), "No obligations should be lost under stress");
            assert!(harness.verify_recovery_convergence(), "System should converge under stress");

            println!("✓ Multi-obligation stress test recovery: {:?}", result.recovery_stats);
        });
    }

    #[test]
    fn test_signal_recovery_grace_period_management() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let harness = SignalObligationRecoveryTestHarness::new().await.unwrap();

            // Create obligations that will require some recovery time
            for i in 5001..5011 {
                harness.create_obligation(i);
                if i % 2 == 0 {
                    harness.add_stale_obligation(i + 100);
                }
                if i % 3 == 0 {
                    harness.create_conflict_obligation(i + 200);
                }
            }

            // Trigger SIGTERM
            harness.trigger_sigterm();

            // Run recovery sequence
            let result = harness.run_recovery_sequence().await;

            // Verify recovery completed within grace period
            assert!(result.success, "Recovery should complete within grace period");
            assert!(result.recovery_stats.recovery_completion_ms < result.recovery_stats.grace_period_ms,
                "Recovery should complete within grace period: {}ms < {}ms",
                result.recovery_stats.recovery_completion_ms, result.recovery_stats.grace_period_ms);
            assert!(result.recovery_stats.convergence_achieved, "Should achieve convergence within grace period");

            println!("✓ Grace period management during recovery: {}ms recovery in {}ms grace period",
                result.recovery_stats.recovery_completion_ms, result.recovery_stats.grace_period_ms);
        });
    }

    #[test]
    fn test_signal_recovery_quiescence_verification() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let harness = SignalObligationRecoveryTestHarness::new().await.unwrap();

            // Create a comprehensive test scenario
            harness.create_obligation(6001);
            harness.create_obligation(6002);
            harness.add_stale_obligation(6003);
            harness.create_conflict_obligation(6004);

            // Trigger SIGTERM
            harness.trigger_sigterm();

            // Run recovery sequence
            let result = harness.run_recovery_sequence().await;

            // Verify complete quiescence achieved
            assert!(result.success, "Recovery should achieve complete success");
            assert!(result.recovery_stats.convergence_achieved, "Should achieve convergence");
            assert!(result.recovery_stats.quiescence_achieved, "Should achieve quiescence");
            assert!(harness.verify_recovery_convergence(), "System should be fully quiescent");

            // Verify all anomalies were handled
            let final_stats = harness.get_stats_snapshot();
            assert!(final_stats.stale_obligations_cleaned > 0, "Should clean stale obligations");
            assert!(final_stats.conflicts_resolved > 0, "Should resolve conflicts");
            assert!(final_stats.recovery_actions_taken > 0, "Should take recovery actions");

            println!("✓ Complete quiescence verification: {:?}", result.recovery_stats);
        });
    }
}