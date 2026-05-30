//! Real obligation/leak_check E2E tests
//!
//! Tests obligation ledger with random spawn/abort sequences to validate
//! zero leaks. Uses real asupersync obligation tracking with comprehensive
//! leak detection and ledger state validation.
//!
//! Focused chaos lane:
//! `RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_obligation_cleanup_e2e" ASUPERSYNC_TEST_ARTIFACTS_DIR=target/e2e-results/obligation-cleanup/artifacts cargo test -p asupersync --no-default-features --features obligation-cleanup-e2e --test obligation_cleanup_e2e test_client_disconnect_forced_cancel_cleans_pending_obligations -- --nocapture --test-threads=1`

use crate::atp::logging::{
    ATP_LOG_EVENT_SCHEMA_VERSION, AtpEvent, AtpLogger, AtpSubsystem, EventContext,
};
use crate::lab::chaos::{ChaosConfig, ChaosStats};
use crate::obligation::ledger::ObligationLedger;
use crate::observability::LogLevel;
use crate::record::{ObligationAbortReason, ObligationKind, SourceLocation};
use crate::runtime::RuntimeBuilder;
use crate::types::{ObligationId, RegionId, TaskId, Time};
use serde_json::{Value, json};
use std::env;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct ObligationCleanupHarness {
    ledger: Arc<Mutex<ObligationLedger>>,
    atp_logger: AtpLogger,
    start_time: Instant,
    logical_time_ns: AtomicU64,
    log_entries: Mutex<Vec<Value>>,
    operations: Mutex<Vec<ObligationOperation>>,
    holder: TaskId,
    region: RegionId,
}

#[derive(Clone, Copy)]
struct ObligationOperation {
    created: bool,
    completed: bool,
    success: bool,
}

#[derive(Clone, Copy)]
struct CleanupChaosFault {
    cancel_requested: bool,
    delay: Option<Duration>,
    budget_exhausted: bool,
}

#[derive(Clone, Copy)]
struct LeakSnapshot {
    total_obligations: usize,
    pending_obligations: usize,
    committed_obligations: usize,
    aborted_obligations: usize,
    leaked_obligations: usize,
    pending_or_leaked_reported: usize,
    ledger_consistent: bool,
}

impl ObligationCleanupHarness {
    fn new() -> Self {
        Self {
            ledger: Arc::new(Mutex::new(ObligationLedger::new())),
            atp_logger: AtpLogger::new(),
            start_time: Instant::now(),
            logical_time_ns: AtomicU64::new(1),
            log_entries: Mutex::new(Vec::new()),
            operations: Mutex::new(Vec::new()),
            holder: TaskId::testing_default(),
            region: RegionId::testing_default(),
        }
    }

    fn next_time(&self) -> Time {
        Time::from_nanos(self.logical_time_ns.fetch_add(1, Ordering::AcqRel))
    }

    fn log(&self, event: &str, data: Value) {
        let timestamp_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis());
        let entry = json!({
            "timestamp_unix_ms": timestamp_unix_ms,
            "event": event,
            "data": data,
            "elapsed_ms": self.start_time.elapsed().as_millis()
        });
        self.log_entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(entry);
    }

    fn atp_event_context(&self) -> EventContext {
        EventContext {
            session_id: "asupersync-9u057b.5".to_string(),
            transfer_id: Some("obligation-cleanup-chaos".to_string()),
            connection_id: None,
            peer_id: None,
            test_case_id: Some("asupersync-9u057b.5".to_string()),
            trace_id: "trace-obligation-cleanup-chaos".to_string(),
            span_id: "root".to_string(),
        }
    }

    fn log_atp_event(&self, event_type: &str, data: Value) {
        let event = AtpEvent {
            schema_version: ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
            timestamp: crate::atp::logging::current_timestamp(),
            level: LogLevel::Info,
            subsystem: AtpSubsystem::E2eTest,
            event_type: event_type.to_string(),
            data,
            context: self.atp_event_context(),
            redacted_fields: Vec::new(),
        };
        let rendered = self
            .atp_logger
            .render_event(&event)
            .expect("ATP obligation cleanup E2E event should satisfy the logging contract");
        let rendered_event: Value =
            serde_json::from_str(&rendered).expect("rendered ATP log event should be JSON");

        self.log(
            "atp_structured_log",
            json!({
                "schema_version": ATP_LOG_EVENT_SCHEMA_VERSION,
                "event_type": event_type,
                "rendered_event": rendered_event
            }),
        );
    }

    fn record_operation(&self, operation: ObligationOperation) {
        self.operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(operation);
    }

    fn create_pending_obligation(&self, kind: ObligationKind, context: &str) -> ObligationId {
        let mut ledger = self
            .ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = ledger.len();
        let token = ledger.acquire_with_context(
            kind,
            self.holder,
            self.region,
            self.next_time(),
            SourceLocation::unknown(),
            None,
            Some(context.to_string()),
        );
        let obligation_id = token.id();
        drop(token);
        let after = ledger.len();
        drop(ledger);

        self.record_operation(ObligationOperation {
            created: true,
            completed: false,
            success: true,
        });
        self.log(
            "obligation_created",
            json!({
                "context": context,
                "kind": kind.as_str(),
                "obligation_id": obligation_id.to_string(),
                "ledger_size_before": before,
                "ledger_size_after": after
            }),
        );

        obligation_id
    }

    fn create_reserved_send(&self, context: &str) -> ObligationId {
        self.create_pending_obligation(ObligationKind::SendPermit, context)
    }

    fn create_pending_ack(&self, context: &str) -> ObligationId {
        self.create_pending_obligation(ObligationKind::Ack, context)
    }

    fn abort_pending_obligation(
        &self,
        obligation_id: ObligationId,
        context: &str,
    ) -> Result<(), String> {
        let mut ledger = self
            .ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = ledger.len();
        let result = ledger.try_abort_by_id(
            obligation_id,
            self.next_time(),
            ObligationAbortReason::Cancel,
        );
        let after = ledger.len();
        drop(ledger);

        match result {
            Ok(duration_ns) => {
                self.record_operation(ObligationOperation {
                    created: false,
                    completed: true,
                    success: true,
                });
                self.log(
                    "obligation_aborted",
                    json!({
                        "context": context,
                        "obligation_id": obligation_id.to_string(),
                        "held_ns": duration_ns,
                        "ledger_size_before": before,
                        "ledger_size_after": after
                    }),
                );
                Ok(())
            }
            Err(error) => {
                self.record_operation(ObligationOperation {
                    created: false,
                    completed: true,
                    success: false,
                });
                Err(error.to_string())
            }
        }
    }

    fn abort_reserved_send(
        &self,
        obligation_id: ObligationId,
        context: &str,
    ) -> Result<(), String> {
        self.abort_pending_obligation(obligation_id, context)
    }

    fn abort_pending_ack(&self, obligation_id: ObligationId, context: &str) -> Result<(), String> {
        self.abort_pending_obligation(obligation_id, context)
    }

    fn snapshot(&self, check_type: &str) -> LeakSnapshot {
        let ledger = self
            .ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stats = ledger.stats();
        let pending_or_leaked_reported = ledger.check_leaks().leaked.len();
        let snapshot = LeakSnapshot {
            total_obligations: ledger.len(),
            pending_obligations: stats.pending as usize,
            committed_obligations: stats.total_committed as usize,
            aborted_obligations: stats.total_aborted as usize,
            leaked_obligations: stats.total_leaked as usize,
            pending_or_leaked_reported,
            ledger_consistent: stats.total_acquired
                == stats
                    .total_committed
                    .saturating_add(stats.total_aborted)
                    .saturating_add(stats.total_leaked)
                    .saturating_add(stats.pending),
        };
        drop(ledger);

        self.log(
            "leak_check",
            json!({
                "check_type": check_type,
                "total": snapshot.total_obligations,
                "pending": snapshot.pending_obligations,
                "committed": snapshot.committed_obligations,
                "aborted": snapshot.aborted_obligations,
                "leaked": snapshot.leaked_obligations,
                "pending_or_leaked_reported": snapshot.pending_or_leaked_reported,
                "consistent": snapshot.ledger_consistent
            }),
        );

        snapshot
    }

    fn validate_zero_leaks(&self) -> Result<(), String> {
        let final_check = self.snapshot("validation");
        if final_check.pending_obligations != 0 {
            return Err(format!(
                "{} obligations still pending",
                final_check.pending_obligations
            ));
        }
        if final_check.leaked_obligations != 0 {
            return Err(format!(
                "Leak detected: {} obligations leaked",
                final_check.leaked_obligations
            ));
        }
        if !final_check.ledger_consistent {
            return Err("ledger conservation check failed".to_string());
        }

        let operations = self
            .operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let creates = operations
            .iter()
            .filter(|operation| operation.success && operation.created)
            .count();
        let completions = operations
            .iter()
            .filter(|operation| operation.success && operation.completed)
            .count();
        if creates != completions {
            return Err(format!(
                "operation count mismatch: {creates} creates vs {completions} completions"
            ));
        }

        Ok(())
    }

    fn write_artifact_bundle(&self, test_id: &str, summary: Value) -> std::io::Result<()> {
        let Ok(root) = env::var("ASUPERSYNC_TEST_ARTIFACTS_DIR") else {
            return Ok(());
        };

        let artifact_dir = Path::new(&root).join(test_id);
        fs::create_dir_all(&artifact_dir)?;
        self.log(
            "artifact_bundle_written",
            json!({
                "test_id": test_id,
                "artifact_dir": artifact_dir.display().to_string(),
                "events_path": artifact_dir.join("events.ndjson").display().to_string(),
                "summary_path": artifact_dir.join("summary.json").display().to_string()
            }),
        );
        self.log_atp_event(
            "artifact_written",
            json!({
                "test_id": test_id,
                "events_path": artifact_dir.join("events.ndjson").display().to_string(),
                "summary_path": artifact_dir.join("summary.json").display().to_string(),
            }),
        );

        let log_entries = self
            .log_entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut events = String::new();
        for entry in log_entries.iter() {
            events.push_str(
                &serde_json::to_string(entry)
                    .expect("structured obligation E2E log entry should serialize"),
            );
            events.push('\n');
        }
        let summary_compact = serde_json::to_string(&summary)
            .expect("structured obligation E2E summary should serialize");
        let summary_pretty = serde_json::to_string_pretty(&summary)
            .expect("structured obligation E2E summary should serialize");

        fs::write(artifact_dir.join("events.ndjson"), &events)?;
        fs::write(artifact_dir.join("summary.json"), &summary_pretty)?;

        println!("ASUPERSYNC_OBLIGATION_CLEANUP_EVENTS_BEGIN {test_id}");
        print!("{events}");
        println!("ASUPERSYNC_OBLIGATION_CLEANUP_EVENTS_END {test_id}");
        println!("ASUPERSYNC_OBLIGATION_CLEANUP_SUMMARY_JSON {summary_compact}");

        Ok(())
    }
}

fn cleanup_chaos_config(seed: u64) -> ChaosConfig {
    ChaosConfig::new(seed)
        .with_cancel_probability(1.0)
        .with_delay_probability(1.0)
        .with_delay_range(Duration::from_millis(1)..Duration::from_millis(3))
        .with_budget_exhaust_probability(0.25)
}

fn build_cleanup_chaos_faults(
    config: &ChaosConfig,
    pending_count: usize,
) -> (Vec<CleanupChaosFault>, ChaosStats) {
    let mut rng = config.rng();
    let mut stats = ChaosStats::new();
    let mut faults = Vec::with_capacity(pending_count);

    for _ in 0..pending_count {
        let cancel_requested = rng.should_inject_cancel(config);
        let delay = rng
            .should_inject_delay(config)
            .then(|| rng.next_delay(config));
        let budget_exhausted = rng.should_inject_budget_exhaust(config);
        stats.record_pre_poll_outcomes(cancel_requested, delay, budget_exhausted);
        faults.push(CleanupChaosFault {
            cancel_requested,
            delay,
            budget_exhausted,
        });
    }

    (faults, stats)
}

/// Runs the focused no-mock client-disconnect obligation cleanup E2E scenario.
///
/// The harness uses the real `ObligationLedger` and a real Asupersync runtime
/// for the cancellation cleanup tasks. It is intentionally exposed only behind
/// the `obligation-cleanup-e2e` feature and invoked by
/// `tests/obligation_cleanup_e2e.rs`.
pub fn run_client_disconnect_forced_cancel_cleanup_e2e() {
    let harness = Arc::new(ObligationCleanupHarness::new());
    let pending_count = 16;
    let cleanup_budget = Duration::from_millis(250);
    let chaos_seed = 0x9005_7B50_u64;
    let chaos_config = cleanup_chaos_config(chaos_seed);
    let chaos_summary = chaos_config.summary();
    let (cleanup_faults, chaos_stats) = build_cleanup_chaos_faults(&chaos_config, pending_count);

    harness.log(
        "test_start",
        json!({
            "test": "client_disconnect_forced_cancel_cleanup",
            "pending_count": pending_count,
            "cleanup_budget_ms": cleanup_budget.as_millis(),
            "chaos_seed": chaos_seed,
            "chaos_summary": chaos_summary
        }),
    );
    harness.log_atp_event(
        "test_started",
        json!({
            "scenario": "client_disconnect_during_reserved_send",
            "pending_count": pending_count,
            "chaos_summary": chaos_summary,
            "cleanup_budget_ms": cleanup_budget.as_millis(),
        }),
    );
    harness.log_atp_event(
        "seed_selected",
        json!({
            "seed": chaos_seed,
            "scenario": "client_disconnect_during_reserved_send",
            "chaos_decision_points": chaos_stats.decision_points,
            "chaos_cancellations": chaos_stats.cancellations,
            "chaos_delays": chaos_stats.delays,
            "chaos_budget_exhaustions": chaos_stats.budget_exhaustions,
        }),
    );

    let initial_check = harness.snapshot("initial");
    assert_eq!(
        initial_check.pending_obligations, 0,
        "should start with zero pending obligations"
    );
    assert_eq!(
        initial_check.leaked_obligations, 0,
        "should start with zero leaked obligations"
    );

    let mut pending_obligations = Vec::with_capacity(pending_count);
    for index in 0..pending_count {
        let obligation_id =
            harness.create_reserved_send(&format!("client_disconnect_reserved_send_{index}"));
        pending_obligations.push(obligation_id);

        if index % 4 == 3 {
            harness.log(
                "stage_progress",
                json!({
                    "stage": "reserve_before_disconnect",
                    "created": index + 1,
                    "pending_so_far": pending_obligations.len()
                }),
            );
        }
    }

    let before_cancel = harness.snapshot("before_forced_cancel");
    assert_eq!(
        before_cancel.pending_obligations, pending_count,
        "all reserved-send obligations should be pending before cleanup"
    );
    assert_eq!(
        before_cancel.leaked_obligations, 0,
        "pending obligations should not be marked leaked before cleanup"
    );

    harness.log(
        "forced_cancel_requested",
        json!({
            "scenario": "client_disconnect_during_reserved_send",
            "pending_before": before_cancel.pending_obligations,
            "leaked_before": before_cancel.leaked_obligations,
            "cleanup_budget_ms": cleanup_budget.as_millis(),
            "chaos_seed": chaos_seed,
            "chaos_summary": chaos_summary,
            "chaos_decision_points": chaos_stats.decision_points,
            "chaos_cancellations": chaos_stats.cancellations,
            "chaos_delays": chaos_stats.delays,
            "chaos_budget_exhaustions": chaos_stats.budget_exhaustions
        }),
    );

    let cleanup_runtime = RuntimeBuilder::new()
        .thread_name_prefix("obligation-chaos-client-disconnect-cleanup")
        .worker_threads(2)
        .build()
        .expect("real cleanup runtime should build for obligation chaos E2E");
    let runtime_handle = cleanup_runtime.handle();
    let cleanup_started = Instant::now();
    let cleanup_tasks_started = Arc::new(AtomicUsize::new(0));
    let cleanup_tasks_completed = Arc::new(AtomicUsize::new(0));
    let cleanup_region_closed = Arc::new(AtomicBool::new(false));
    let mut cleanup_handles = Vec::with_capacity(pending_obligations.len());

    for (index, obligation_id) in pending_obligations.iter().copied().enumerate() {
        let cleanup_harness = Arc::clone(&harness);
        let tasks_started = Arc::clone(&cleanup_tasks_started);
        let tasks_completed = Arc::clone(&cleanup_tasks_completed);
        let fault = cleanup_faults[index];
        let handle = runtime_handle.spawn(async move {
            tasks_started.fetch_add(1, Ordering::AcqRel);
            if let Some(delay) = fault.delay {
                std::thread::sleep(delay);
            }
            if fault.budget_exhausted {
                std::thread::yield_now();
            }
            cleanup_harness.log(
                "chaos_fault_injected",
                json!({
                    "stage": "forced_cancel_cleanup_task",
                    "task_index": index,
                    "cancel_requested": fault.cancel_requested,
                    "delay_ms": fault.delay.map_or(0, |delay| delay.as_millis()),
                    "budget_exhausted": fault.budget_exhausted
                }),
            );
            assert!(
                fault.cancel_requested,
                "forced-cancel chaos plan must request cancellation for every pending obligation"
            );
            cleanup_harness
                .abort_reserved_send(obligation_id, "client_disconnect_forced_cancel")
                .expect("forced cancellation should abort every pending obligation");
            let completed = tasks_completed.fetch_add(1, Ordering::AcqRel) + 1;

            if index % 4 == 3 {
                cleanup_harness.log(
                    "stage_progress",
                    json!({
                        "stage": "abort_pending_after_disconnect",
                        "aborted": completed
                    }),
                );
            }
        });
        cleanup_handles.push(handle);
    }

    cleanup_runtime.block_on(async {
        for handle in cleanup_handles {
            handle.await;
        }
    });
    cleanup_region_closed.store(true, Ordering::Release);
    let cleanup_elapsed = cleanup_started.elapsed();

    let after_cancel = harness.snapshot("after_forced_cancel");
    let cleanup_task_start_count = cleanup_tasks_started.load(Ordering::Acquire);
    let cleanup_task_complete_count = cleanup_tasks_completed.load(Ordering::Acquire);
    let cleanup_region_is_closed = cleanup_region_closed.load(Ordering::Acquire);
    let cleanup_runtime_is_quiescent = cleanup_runtime.is_quiescent();

    harness.log(
        "forced_cancel_cleanup_complete",
        json!({
            "pending_before": before_cancel.pending_obligations,
            "pending_after": after_cancel.pending_obligations,
            "leaked_after": after_cancel.leaked_obligations,
            "ledger_consistent": after_cancel.ledger_consistent,
            "cleanup_tasks_started": cleanup_task_start_count,
            "cleanup_tasks_completed": cleanup_task_complete_count,
            "cleanup_region_closed": cleanup_region_is_closed,
            "cleanup_runtime_quiescent": cleanup_runtime_is_quiescent,
            "region_close_implies_quiescence": cleanup_region_is_closed && cleanup_runtime_is_quiescent,
            "cleanup_elapsed_ms": cleanup_elapsed.as_millis(),
            "cleanup_budget_ms": cleanup_budget.as_millis(),
            "chaos_seed": chaos_seed,
            "chaos_decision_points": chaos_stats.decision_points,
            "chaos_cancellations": chaos_stats.cancellations,
            "chaos_delays": chaos_stats.delays,
            "chaos_budget_exhaustions": chaos_stats.budget_exhaustions,
            "chaos_total_delay_ms": chaos_stats.total_delay.as_millis()
        }),
    );

    assert_eq!(
        chaos_stats.decision_points as usize, pending_count,
        "chaos plan should include one cleanup fault decision per pending obligation"
    );
    assert_eq!(
        chaos_stats.cancellations as usize, pending_count,
        "forced-cancel chaos plan should inject cancellation at every cleanup decision"
    );
    assert!(
        cleanup_elapsed <= cleanup_budget,
        "forced cancellation cleanup exceeded budget: {:?} > {:?}",
        cleanup_elapsed,
        cleanup_budget
    );
    assert_eq!(
        after_cancel.pending_obligations, 0,
        "forced cancellation must resolve all pending obligations"
    );
    assert_eq!(
        after_cancel.leaked_obligations, 0,
        "forced cancellation must not leak obligations"
    );
    assert_eq!(
        cleanup_task_start_count, pending_count,
        "forced cancellation should spawn one cleanup task per pending obligation"
    );
    assert_eq!(
        cleanup_task_complete_count, pending_count,
        "forced cancellation cleanup tasks must all complete"
    );
    assert!(
        cleanup_region_is_closed,
        "cleanup region marker should close after all cleanup tasks join"
    );
    assert!(
        cleanup_runtime_is_quiescent,
        "cleanup runtime should be quiescent after forced cancellation joins"
    );
    assert!(
        after_cancel.ledger_consistent,
        "ledger should remain consistent after forced cancellation cleanup"
    );

    let validation_result = harness.validate_zero_leaks();
    assert!(
        validation_result.is_ok(),
        "forced cancellation leak validation failed: {:?}",
        validation_result
    );
    harness.log_atp_event(
        "oracle_checked",
        json!({
            "oracle": "obligation_cleanup_no_leak",
            "zero_pending": after_cancel.pending_obligations == 0,
            "zero_leaks": after_cancel.leaked_obligations == 0,
            "ledger_consistent": after_cancel.ledger_consistent,
            "region_close_implies_quiescence": cleanup_region_is_closed && cleanup_runtime_is_quiescent,
            "chaos_cancellations": chaos_stats.cancellations,
        }),
    );

    harness.log(
        "test_result",
        json!({
            "passed": true,
            "scenario": "client_disconnect_during_reserved_send",
            "zero_pending": after_cancel.pending_obligations == 0,
            "zero_leaks": after_cancel.leaked_obligations == 0,
            "no_task_leaks": cleanup_task_complete_count == pending_count,
            "region_close_implies_quiescence": cleanup_region_is_closed && cleanup_runtime_is_quiescent,
            "cleanup_within_budget": cleanup_elapsed <= cleanup_budget,
            "chaos_seed": chaos_seed,
            "chaos_decision_points": chaos_stats.decision_points,
            "chaos_cancellations": chaos_stats.cancellations,
            "chaos_delays": chaos_stats.delays,
            "chaos_budget_exhaustions": chaos_stats.budget_exhaustions
        }),
    );
    harness.log_atp_event(
        "test_completed",
        json!({
            "passed": true,
            "scenario": "client_disconnect_during_reserved_send",
            "cleanup_elapsed_ms": cleanup_elapsed.as_millis(),
            "cleanup_budget_ms": cleanup_budget.as_millis(),
            "chaos_seed": chaos_seed,
        }),
    );

    harness
        .write_artifact_bundle(
            "client_disconnect_forced_cancel_cleanup",
            json!({
                "schema_version": "obligation-chaos-e2e-summary-v1",
                "scenario": "client_disconnect_during_reserved_send",
                "pending_before": before_cancel.pending_obligations,
                "pending_after": after_cancel.pending_obligations,
                "leaked_after": after_cancel.leaked_obligations,
                "ledger_consistent": after_cancel.ledger_consistent,
                "cleanup_tasks_started": cleanup_task_start_count,
                "cleanup_tasks_completed": cleanup_task_complete_count,
                "cleanup_region_closed": cleanup_region_is_closed,
                "cleanup_runtime_quiescent": cleanup_runtime_is_quiescent,
                "cleanup_elapsed_ms": cleanup_elapsed.as_millis(),
                "cleanup_budget_ms": cleanup_budget.as_millis(),
                "atp_log_schema_version": ATP_LOG_EVENT_SCHEMA_VERSION,
                "chaos_seed": chaos_seed,
                "chaos_summary": chaos_summary,
                "chaos_decision_points": chaos_stats.decision_points,
                "chaos_cancellations": chaos_stats.cancellations,
                "chaos_delays": chaos_stats.delays,
                "chaos_budget_exhaustions": chaos_stats.budget_exhaustions,
                "chaos_total_delay_ms": chaos_stats.total_delay.as_millis()
            }),
        )
        .expect("artifact bundle should be written when artifact env is set");
}

/// Runs the no-mock supervisor-restart cleanup scenario for pending ack obligations.
///
/// This complements the client-disconnect send-permit scenario by proving that
/// restart recovery aborts outstanding acknowledgements without leaving pending
/// obligations or live cleanup tasks behind.
pub fn run_supervisor_restart_pending_ack_cleanup_e2e() {
    let harness = Arc::new(ObligationCleanupHarness::new());
    let pending_count = 12;
    let cleanup_budget = Duration::from_millis(250);
    let chaos_seed = 0x9005_7B51_u64;
    let chaos_config = cleanup_chaos_config(chaos_seed);
    let chaos_summary = chaos_config.summary();
    let (cleanup_faults, chaos_stats) = build_cleanup_chaos_faults(&chaos_config, pending_count);

    harness.log(
        "test_start",
        json!({
            "test": "supervisor_restart_pending_ack_cleanup",
            "pending_count": pending_count,
            "cleanup_budget_ms": cleanup_budget.as_millis(),
            "chaos_seed": chaos_seed,
            "chaos_summary": chaos_summary
        }),
    );
    harness.log_atp_event(
        "test_started",
        json!({
            "scenario": "supervisor_restart_during_pending_ack",
            "pending_count": pending_count,
            "chaos_summary": chaos_summary,
            "cleanup_budget_ms": cleanup_budget.as_millis(),
        }),
    );
    harness.log_atp_event(
        "seed_selected",
        json!({
            "seed": chaos_seed,
            "scenario": "supervisor_restart_during_pending_ack",
            "chaos_decision_points": chaos_stats.decision_points,
            "chaos_cancellations": chaos_stats.cancellations,
            "chaos_delays": chaos_stats.delays,
            "chaos_budget_exhaustions": chaos_stats.budget_exhaustions,
        }),
    );

    let initial_check = harness.snapshot("initial");
    assert_eq!(
        initial_check.pending_obligations, 0,
        "should start with zero pending obligations"
    );
    assert_eq!(
        initial_check.leaked_obligations, 0,
        "should start with zero leaked obligations"
    );

    let mut pending_obligations = Vec::with_capacity(pending_count);
    for index in 0..pending_count {
        let obligation_id = harness.create_pending_ack(&format!("supervisor_restart_ack_{index}"));
        pending_obligations.push(obligation_id);

        if index % 3 == 2 {
            harness.log(
                "stage_progress",
                json!({
                    "stage": "ack_pending_before_restart",
                    "created": index + 1,
                    "pending_so_far": pending_obligations.len()
                }),
            );
        }
    }

    let before_restart = harness.snapshot("before_supervisor_restart");
    assert_eq!(
        before_restart.pending_obligations, pending_count,
        "all ack obligations should be pending before supervisor restart"
    );
    assert_eq!(
        before_restart.leaked_obligations, 0,
        "pending ack obligations should not be marked leaked before cleanup"
    );

    harness.log(
        "supervisor_restart_requested",
        json!({
            "scenario": "supervisor_restart_during_pending_ack",
            "pending_before": before_restart.pending_obligations,
            "leaked_before": before_restart.leaked_obligations,
            "cleanup_budget_ms": cleanup_budget.as_millis(),
            "chaos_seed": chaos_seed,
            "chaos_summary": chaos_summary,
            "chaos_decision_points": chaos_stats.decision_points,
            "chaos_cancellations": chaos_stats.cancellations,
            "chaos_delays": chaos_stats.delays,
            "chaos_budget_exhaustions": chaos_stats.budget_exhaustions
        }),
    );

    let cleanup_runtime = RuntimeBuilder::new()
        .thread_name_prefix("obligation-chaos-supervisor-restart-cleanup")
        .worker_threads(2)
        .build()
        .expect("real cleanup runtime should build for supervisor restart E2E");
    let runtime_handle = cleanup_runtime.handle();
    let cleanup_started = Instant::now();
    let cleanup_tasks_started = Arc::new(AtomicUsize::new(0));
    let cleanup_tasks_completed = Arc::new(AtomicUsize::new(0));
    let cleanup_region_closed = Arc::new(AtomicBool::new(false));
    let mut cleanup_handles = Vec::with_capacity(pending_obligations.len());

    for (index, obligation_id) in pending_obligations.iter().copied().enumerate() {
        let cleanup_harness = Arc::clone(&harness);
        let tasks_started = Arc::clone(&cleanup_tasks_started);
        let tasks_completed = Arc::clone(&cleanup_tasks_completed);
        let fault = cleanup_faults[index];
        let handle = runtime_handle.spawn(async move {
            tasks_started.fetch_add(1, Ordering::AcqRel);
            if let Some(delay) = fault.delay {
                std::thread::sleep(delay);
            }
            if fault.budget_exhausted {
                std::thread::yield_now();
            }
            cleanup_harness.log(
                "chaos_fault_injected",
                json!({
                    "stage": "supervisor_restart_cleanup_task",
                    "task_index": index,
                    "cancel_requested": fault.cancel_requested,
                    "delay_ms": fault.delay.map_or(0, |delay| delay.as_millis()),
                    "budget_exhausted": fault.budget_exhausted
                }),
            );
            assert!(
                fault.cancel_requested,
                "restart chaos plan must cancel every pending ack obligation"
            );
            cleanup_harness
                .abort_pending_ack(obligation_id, "supervisor_restart_cleanup")
                .expect("supervisor restart cleanup should abort every pending ack obligation");
            let completed = tasks_completed.fetch_add(1, Ordering::AcqRel) + 1;

            if index % 3 == 2 {
                cleanup_harness.log(
                    "stage_progress",
                    json!({
                        "stage": "abort_pending_ack_after_restart",
                        "aborted": completed
                    }),
                );
            }
        });
        cleanup_handles.push(handle);
    }

    cleanup_runtime.block_on(async {
        for handle in cleanup_handles {
            handle.await;
        }
    });
    cleanup_region_closed.store(true, Ordering::Release);
    let cleanup_elapsed = cleanup_started.elapsed();

    let after_restart = harness.snapshot("after_supervisor_restart_cleanup");
    let cleanup_task_start_count = cleanup_tasks_started.load(Ordering::Acquire);
    let cleanup_task_complete_count = cleanup_tasks_completed.load(Ordering::Acquire);
    let cleanup_region_is_closed = cleanup_region_closed.load(Ordering::Acquire);
    let cleanup_runtime_is_quiescent = cleanup_runtime.is_quiescent();

    harness.log(
        "supervisor_restart_cleanup_complete",
        json!({
            "pending_before": before_restart.pending_obligations,
            "pending_after": after_restart.pending_obligations,
            "leaked_after": after_restart.leaked_obligations,
            "ledger_consistent": after_restart.ledger_consistent,
            "cleanup_tasks_started": cleanup_task_start_count,
            "cleanup_tasks_completed": cleanup_task_complete_count,
            "cleanup_region_closed": cleanup_region_is_closed,
            "cleanup_runtime_quiescent": cleanup_runtime_is_quiescent,
            "region_close_implies_quiescence": cleanup_region_is_closed && cleanup_runtime_is_quiescent,
            "cleanup_elapsed_ms": cleanup_elapsed.as_millis(),
            "cleanup_budget_ms": cleanup_budget.as_millis(),
            "chaos_seed": chaos_seed,
            "chaos_decision_points": chaos_stats.decision_points,
            "chaos_cancellations": chaos_stats.cancellations,
            "chaos_delays": chaos_stats.delays,
            "chaos_budget_exhaustions": chaos_stats.budget_exhaustions,
            "chaos_total_delay_ms": chaos_stats.total_delay.as_millis()
        }),
    );

    assert_eq!(
        chaos_stats.decision_points as usize, pending_count,
        "chaos plan should include one cleanup fault decision per pending ack obligation"
    );
    assert_eq!(
        chaos_stats.cancellations as usize, pending_count,
        "restart cleanup chaos plan should inject cancellation at every cleanup decision"
    );
    assert!(
        cleanup_elapsed <= cleanup_budget,
        "supervisor restart cleanup exceeded budget: {:?} > {:?}",
        cleanup_elapsed,
        cleanup_budget
    );
    assert_eq!(
        after_restart.pending_obligations, 0,
        "supervisor restart cleanup must resolve all pending ack obligations"
    );
    assert_eq!(
        after_restart.leaked_obligations, 0,
        "supervisor restart cleanup must not leak ack obligations"
    );
    assert_eq!(
        cleanup_task_start_count, pending_count,
        "supervisor restart cleanup should spawn one cleanup task per pending ack obligation"
    );
    assert_eq!(
        cleanup_task_complete_count, pending_count,
        "supervisor restart cleanup tasks must all complete"
    );
    assert!(
        cleanup_region_is_closed,
        "cleanup region marker should close after all restart cleanup tasks join"
    );
    assert!(
        cleanup_runtime_is_quiescent,
        "cleanup runtime should be quiescent after supervisor restart cleanup joins"
    );
    assert!(
        after_restart.ledger_consistent,
        "ledger should remain consistent after supervisor restart cleanup"
    );

    let validation_result = harness.validate_zero_leaks();
    assert!(
        validation_result.is_ok(),
        "supervisor restart leak validation failed: {:?}",
        validation_result
    );
    harness.log_atp_event(
        "oracle_checked",
        json!({
            "oracle": "obligation_cleanup_no_leak",
            "zero_pending": after_restart.pending_obligations == 0,
            "zero_leaks": after_restart.leaked_obligations == 0,
            "ledger_consistent": after_restart.ledger_consistent,
            "region_close_implies_quiescence": cleanup_region_is_closed && cleanup_runtime_is_quiescent,
            "chaos_cancellations": chaos_stats.cancellations,
        }),
    );

    harness.log(
        "test_result",
        json!({
            "passed": true,
            "scenario": "supervisor_restart_during_pending_ack",
            "zero_pending": after_restart.pending_obligations == 0,
            "zero_leaks": after_restart.leaked_obligations == 0,
            "no_task_leaks": cleanup_task_complete_count == pending_count,
            "region_close_implies_quiescence": cleanup_region_is_closed && cleanup_runtime_is_quiescent,
            "cleanup_within_budget": cleanup_elapsed <= cleanup_budget,
            "chaos_seed": chaos_seed,
            "chaos_decision_points": chaos_stats.decision_points,
            "chaos_cancellations": chaos_stats.cancellations,
            "chaos_delays": chaos_stats.delays,
            "chaos_budget_exhaustions": chaos_stats.budget_exhaustions
        }),
    );
    harness.log_atp_event(
        "test_completed",
        json!({
            "passed": true,
            "scenario": "supervisor_restart_during_pending_ack",
            "cleanup_elapsed_ms": cleanup_elapsed.as_millis(),
            "cleanup_budget_ms": cleanup_budget.as_millis(),
            "chaos_seed": chaos_seed,
        }),
    );

    harness
        .write_artifact_bundle(
            "supervisor_restart_pending_ack_cleanup",
            json!({
                "schema_version": "obligation-chaos-e2e-summary-v1",
                "scenario": "supervisor_restart_during_pending_ack",
                "pending_before": before_restart.pending_obligations,
                "pending_after": after_restart.pending_obligations,
                "leaked_after": after_restart.leaked_obligations,
                "ledger_consistent": after_restart.ledger_consistent,
                "cleanup_tasks_started": cleanup_task_start_count,
                "cleanup_tasks_completed": cleanup_task_complete_count,
                "cleanup_region_closed": cleanup_region_is_closed,
                "cleanup_runtime_quiescent": cleanup_runtime_is_quiescent,
                "cleanup_elapsed_ms": cleanup_elapsed.as_millis(),
                "cleanup_budget_ms": cleanup_budget.as_millis(),
                "atp_log_schema_version": ATP_LOG_EVENT_SCHEMA_VERSION,
                "chaos_seed": chaos_seed,
                "chaos_summary": chaos_summary,
                "chaos_decision_points": chaos_stats.decision_points,
                "chaos_cancellations": chaos_stats.cancellations,
                "chaos_delays": chaos_stats.delays,
                "chaos_budget_exhaustions": chaos_stats.budget_exhaustions,
                "chaos_total_delay_ms": chaos_stats.total_delay.as_millis()
            }),
        )
        .expect("artifact bundle should be written when artifact env is set");
}
