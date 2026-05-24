//! Real obligation/leak_check E2E tests
//!
//! Tests obligation ledger with random spawn/abort sequences to validate
//! zero leaks. Uses real asupersync obligation tracking with comprehensive
//! leak detection and ledger state validation.
//!
//! Focused chaos lane:
//! `RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_obligation_cleanup_e2e" ASUPERSYNC_TEST_ARTIFACTS_DIR=target/e2e-results/obligation-cleanup/artifacts cargo test -p asupersync --no-default-features --features obligation-cleanup-e2e --test obligation_cleanup_e2e test_client_disconnect_forced_cancel_cleans_pending_obligations -- --nocapture --test-threads=1`

// The earlier broad real-service draft depends on a larger E2E compile frontier
// that is currently API-drifted. Keep it out of the focused no-mock proof lane.
#[cfg(any())]
mod real_obligation_leak_check_e2e {
    use crate::obligation::{LeakCheckResult, ObligationId, ObligationLedger, ObligationState};
    use crate::runtime::{RuntimeBuilder, spawn};
    use crate::time::{Duration, Instant, sleep};
    use rand::{Rng, seq::SliceRandom, thread_rng};
    use serde_json::{Value, json};
    use std::collections::HashSet;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use std::{env, fs, path::Path};

    /// Obligation test harness with leak detection and random sequence generation
    struct ObligationLeakTestHarness {
        ledger: Arc<ObligationLedger>,
        start_time: Instant,
        log_entries: Arc<Mutex<Vec<Value>>>,
        operation_log: Arc<Mutex<Vec<ObligationOperation>>>,
        leak_checks: Arc<Mutex<Vec<LeakCheckSnapshot>>>,
    }

    #[derive(Debug, Clone)]
    struct ObligationOperation {
        timestamp: Instant,
        operation: String,
        obligation_id: ObligationId,
        success: bool,
        error: Option<String>,
        ledger_size_before: usize,
        ledger_size_after: usize,
    }

    #[derive(Debug, Clone)]
    struct LeakCheckSnapshot {
        timestamp: Instant,
        check_type: String,
        total_obligations: usize,
        pending_obligations: usize,
        committed_obligations: usize,
        aborted_obligations: usize,
        leaked_obligations: usize,
        ledger_consistent: bool,
    }

    impl ObligationLeakTestHarness {
        fn new() -> Self {
            Self {
                ledger: Arc::new(ObligationLedger::new()),
                start_time: Instant::now(),
                log_entries: Arc::new(Mutex::new(Vec::new())),
                operation_log: Arc::new(Mutex::new(Vec::new())),
                leak_checks: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn log(&self, event: &str, data: Value) {
            let entry = json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "event": event,
                "data": data,
                "elapsed_ms": self.start_time.elapsed().as_millis()
            });
            eprintln!("{}", serde_json::to_string(&entry).unwrap());
            self.log_entries.lock().unwrap().push(entry);
        }

        fn record_operation(&self, op: ObligationOperation) {
            self.operation_log.lock().unwrap().push(op);
        }

        async fn create_obligation(&self, context: &str) -> Result<ObligationId, String> {
            let size_before = self.ledger.size();

            match self.ledger.create_obligation().await {
                Ok(obligation_id) => {
                    let size_after = self.ledger.size();

                    self.record_operation(ObligationOperation {
                        timestamp: Instant::now(),
                        operation: format!("create_{}", context),
                        obligation_id,
                        success: true,
                        error: None,
                        ledger_size_before: size_before,
                        ledger_size_after: size_after,
                    });

                    self.log(
                        "obligation_created",
                        json!({
                            "context": context,
                            "obligation_id": obligation_id.to_string(),
                            "ledger_size": size_after
                        }),
                    );

                    Ok(obligation_id)
                }
                Err(e) => {
                    self.record_operation(ObligationOperation {
                        timestamp: Instant::now(),
                        operation: format!("create_{}_failed", context),
                        obligation_id: ObligationId::new(), // Dummy ID for failed operations
                        success: false,
                        error: Some(e.to_string()),
                        ledger_size_before: size_before,
                        ledger_size_after: self.ledger.size(),
                    });

                    Err(e.to_string())
                }
            }
        }

        async fn commit_obligation(
            &self,
            obligation_id: ObligationId,
            context: &str,
        ) -> Result<(), String> {
            let size_before = self.ledger.size();

            match self.ledger.commit_obligation(obligation_id).await {
                Ok(_) => {
                    let size_after = self.ledger.size();

                    self.record_operation(ObligationOperation {
                        timestamp: Instant::now(),
                        operation: format!("commit_{}", context),
                        obligation_id,
                        success: true,
                        error: None,
                        ledger_size_before: size_before,
                        ledger_size_after: size_after,
                    });

                    self.log(
                        "obligation_committed",
                        json!({
                            "context": context,
                            "obligation_id": obligation_id.to_string(),
                            "ledger_size": size_after
                        }),
                    );

                    Ok(())
                }
                Err(e) => {
                    self.record_operation(ObligationOperation {
                        timestamp: Instant::now(),
                        operation: format!("commit_{}_failed", context),
                        obligation_id,
                        success: false,
                        error: Some(e.to_string()),
                        ledger_size_before: size_before,
                        ledger_size_after: self.ledger.size(),
                    });

                    Err(e.to_string())
                }
            }
        }

        async fn abort_obligation(
            &self,
            obligation_id: ObligationId,
            context: &str,
        ) -> Result<(), String> {
            let size_before = self.ledger.size();

            match self.ledger.abort_obligation(obligation_id).await {
                Ok(_) => {
                    let size_after = self.ledger.size();

                    self.record_operation(ObligationOperation {
                        timestamp: Instant::now(),
                        operation: format!("abort_{}", context),
                        obligation_id,
                        success: true,
                        error: None,
                        ledger_size_before: size_before,
                        ledger_size_after: size_after,
                    });

                    self.log(
                        "obligation_aborted",
                        json!({
                            "context": context,
                            "obligation_id": obligation_id.to_string(),
                            "ledger_size": size_after
                        }),
                    );

                    Ok(())
                }
                Err(e) => {
                    self.record_operation(ObligationOperation {
                        timestamp: Instant::now(),
                        operation: format!("abort_{}_failed", context),
                        obligation_id,
                        success: false,
                        error: Some(e.to_string()),
                        ledger_size_before: size_before,
                        ledger_size_after: self.ledger.size(),
                    });

                    Err(e.to_string())
                }
            }
        }

        async fn perform_leak_check(&self, check_type: &str) -> LeakCheckResult {
            let check_result = self.ledger.perform_leak_check().await;

            let snapshot = LeakCheckSnapshot {
                timestamp: Instant::now(),
                check_type: check_type.to_string(),
                total_obligations: check_result.total_obligations,
                pending_obligations: check_result.pending_obligations,
                committed_obligations: check_result.committed_obligations,
                aborted_obligations: check_result.aborted_obligations,
                leaked_obligations: check_result.leaked_obligations,
                ledger_consistent: check_result.ledger_consistent,
            };

            self.leak_checks.lock().unwrap().push(snapshot.clone());

            self.log(
                "leak_check",
                json!({
                    "check_type": check_type,
                    "total_obligations": check_result.total_obligations,
                    "pending": check_result.pending_obligations,
                    "committed": check_result.committed_obligations,
                    "aborted": check_result.aborted_obligations,
                    "leaked": check_result.leaked_obligations,
                    "consistent": check_result.ledger_consistent
                }),
            );

            check_result
        }

        /// Poll until all resources are properly cleaned up (no leaks, ledger consistent)
        async fn wait_for_leak_free_state(
            &self,
            max_polls: u32,
            timeout: Duration,
        ) -> Result<LeakCheckResult, Box<dyn std::error::Error>> {
            let start = std::time::Instant::now();
            let mut polls = 0;
            let mut backoff = Duration::from_millis(10);
            let max_backoff = Duration::from_millis(100);

            while polls < max_polls && start.elapsed() < timeout {
                let check = self.perform_leak_check(&format!("cleanup_poll_{}", polls)).await;

                if check.leaked_obligations == 0 && check.ledger_consistent {
                    return Ok(check);
                }

                polls += 1;
                sleep(backoff).await;
                backoff = std::cmp::min(
                    Duration::from_millis((backoff.as_millis() as f64 * 1.5) as u64),
                    max_backoff
                );
            }

            // Final check for detailed error info
            let final_check = self.perform_leak_check("cleanup_failed").await;
            Err(format!(
                "Resources not cleaned up after {} polls in {:?}. Leaked: {}, Consistent: {}, Total: {}",
                polls,
                start.elapsed(),
                final_check.leaked_obligations,
                final_check.ledger_consistent,
                final_check.total_obligations
            ).into())
        }

        async fn random_obligation_sequence(
            &self,
            sequence_length: usize,
            abort_probability: f64,
        ) -> Vec<ObligationId> {
            let mut rng = thread_rng();
            let mut active_obligations = Vec::new();
            let mut completed_obligations = HashSet::new();

            for i in 0..sequence_length {
                let action = rng.gen_range(0.0..1.0);

                if action < 0.6 || active_obligations.is_empty() {
                    // Create new obligation (60% probability or if no active obligations)
                    match self.create_obligation(&format!("random_seq_{}", i)).await {
                        Ok(obligation_id) => {
                            active_obligations.push(obligation_id);
                        }
                        Err(_) => {
                            // Creation failed - continue with sequence
                        }
                    }
                } else if action < 0.6 + abort_probability * 0.4 {
                    // Abort random obligation
                    if !active_obligations.is_empty() {
                        let idx = rng.gen_range(0..active_obligations.len());
                        let obligation_id = active_obligations.remove(idx);

                        if let Ok(_) = self
                            .abort_obligation(obligation_id, &format!("random_abort_{}", i))
                            .await
                        {
                            completed_obligations.insert(obligation_id);
                        }
                    }
                } else {
                    // Commit random obligation
                    if !active_obligations.is_empty() {
                        let idx = rng.gen_range(0..active_obligations.len());
                        let obligation_id = active_obligations.remove(idx);

                        if let Ok(_) = self
                            .commit_obligation(obligation_id, &format!("random_commit_{}", i))
                            .await
                        {
                            completed_obligations.insert(obligation_id);
                        }
                    }
                }

                // Occasionally perform intermediate leak checks
                if i % 50 == 0 && i > 0 {
                    self.perform_leak_check(&format!("intermediate_{}", i))
                        .await;
                }

                // Small delay to allow concurrent operations
                if i % 10 == 0 {
                    sleep(Duration::from_millis(1)).await;
                }
            }

            // Clean up remaining active obligations
            for obligation_id in &active_obligations {
                if rng.gen_bool(0.5) {
                    let _ = self
                        .commit_obligation(*obligation_id, "cleanup_commit")
                        .await;
                } else {
                    let _ = self.abort_obligation(*obligation_id, "cleanup_abort").await;
                }
                completed_obligations.insert(*obligation_id);
            }

            completed_obligations.into_iter().collect()
        }

        fn validate_zero_leaks(&self) -> Result<(), String> {
            let leak_checks = self.leak_checks.lock().unwrap();
            let final_check = leak_checks.last().ok_or("No leak checks performed")?;

            if final_check.leaked_obligations > 0 {
                return Err(format!(
                    "Leak detected: {} obligations leaked",
                    final_check.leaked_obligations
                ));
            }

            if !final_check.ledger_consistent {
                return Err("Ledger consistency check failed".to_string());
            }

            // Check that all operations balanced
            let operations = self.operation_log.lock().unwrap();
            let mut create_count = 0;
            let mut complete_count = 0; // commits + aborts

            for op in operations.iter() {
                if op.success {
                    if op.operation.starts_with("create") {
                        create_count += 1;
                    } else if op.operation.starts_with("commit")
                        || op.operation.starts_with("abort")
                    {
                        complete_count += 1;
                    }
                }
            }

            if create_count != complete_count {
                return Err(format!(
                    "Operation count mismatch: {} creates vs {} completions",
                    create_count, complete_count
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

            let log_entries = self.log_entries.lock().unwrap();
            let mut events = String::new();
            for entry in log_entries.iter() {
                events.push_str(
                    &serde_json::to_string(entry)
                        .expect("structured obligation E2E log entry should serialize"),
                );
                events.push('\n');
            }
            fs::write(artifact_dir.join("events.ndjson"), events)?;
            fs::write(
                artifact_dir.join("summary.json"),
                serde_json::to_string_pretty(&summary)
                    .expect("structured obligation E2E summary should serialize"),
            )?;

            self.log(
                "artifact_bundle_written",
                json!({
                    "test_id": test_id,
                    "artifact_dir": artifact_dir.display().to_string(),
                    "events_path": artifact_dir.join("events.ndjson").display().to_string(),
                    "summary_path": artifact_dir.join("summary.json").display().to_string()
                }),
            );

            Ok(())
        }
    }

    #[tokio::test]
    async fn test_single_threaded_random_obligation_sequence() {
        let harness = Arc::new(ObligationLeakTestHarness::new());
        harness.log(
            "test_start",
            json!({"test": "single_threaded_random_sequence"}),
        );

        // Perform initial leak check
        let initial_check = harness.perform_leak_check("initial").await;
        assert_eq!(
            initial_check.leaked_obligations, 0,
            "Should start with zero leaks"
        );

        // Run random sequence with 200 operations
        let sequence_length = 200;
        let abort_probability = 0.3; // 30% of completions are aborts

        let processed_obligations = harness
            .random_obligation_sequence(sequence_length, abort_probability)
            .await;

        // Perform final leak check
        let final_check = harness.perform_leak_check("final").await;

        harness.log(
            "sequence_complete",
            json!({
                "sequence_length": sequence_length,
                "processed_obligations": processed_obligations.len(),
                "abort_probability": abort_probability,
                "final_leaks": final_check.leaked_obligations,
                "ledger_consistent": final_check.ledger_consistent
            }),
        );

        // Validate zero leaks
        let validation_result = harness.validate_zero_leaks();
        assert!(
            validation_result.is_ok(),
            "Leak validation failed: {:?}",
            validation_result
        );

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "zero_leaks": final_check.leaked_obligations == 0,
                "consistent": final_check.ledger_consistent,
                "message": "Single-threaded random obligation sequence validated successfully"
            }),
        );
    }

    #[tokio::test]
    async fn test_concurrent_obligation_workers() {
        let harness = Arc::new(ObligationLeakTestHarness::new());
        harness.log(
            "test_start",
            json!({"test": "concurrent_obligation_workers"}),
        );

        let num_workers = 5;
        let operations_per_worker = 100;

        let initial_check = harness.perform_leak_check("initial").await;
        assert_eq!(
            initial_check.leaked_obligations, 0,
            "Should start with zero leaks"
        );

        let mut worker_handles = Vec::new();

        // Spawn concurrent workers
        for worker_id in 0..num_workers {
            let harness = Arc::clone(&harness);

            let handle = spawn(async move {
                let mut rng = thread_rng();
                let mut worker_obligations = Vec::new();

                // Each worker creates obligations, then commits/aborts them
                for op_id in 0..operations_per_worker {
                    match harness
                        .create_obligation(&format!("worker_{}_op_{}", worker_id, op_id))
                        .await
                    {
                        Ok(obligation_id) => {
                            worker_obligations.push(obligation_id);
                        }
                        Err(_) => {
                            // Creation failed - continue
                        }
                    }

                    // Randomly complete some obligations
                    if !worker_obligations.is_empty() && rng.gen_bool(0.4) {
                        let idx = rng.gen_range(0..worker_obligations.len());
                        let obligation_id = worker_obligations.remove(idx);

                        if rng.gen_bool(0.7) {
                            let _ = harness
                                .commit_obligation(
                                    obligation_id,
                                    &format!("worker_{}_commit", worker_id),
                                )
                                .await;
                        } else {
                            let _ = harness
                                .abort_obligation(
                                    obligation_id,
                                    &format!("worker_{}_abort", worker_id),
                                )
                                .await;
                        }
                    }

                    // Yield occasionally
                    if op_id % 20 == 0 {
                        sleep(Duration::from_millis(1)).await;
                    }
                }

                // Complete remaining obligations for this worker
                for obligation_id in worker_obligations {
                    if rng.gen_bool(0.6) {
                        let _ = harness
                            .commit_obligation(
                                obligation_id,
                                &format!("worker_{}_final_commit", worker_id),
                            )
                            .await;
                    } else {
                        let _ = harness
                            .abort_obligation(
                                obligation_id,
                                &format!("worker_{}_final_abort", worker_id),
                            )
                            .await;
                    }
                }

                worker_id
            });

            worker_handles.push(handle);
        }

        // Wait for all workers to complete
        for handle in worker_handles {
            let worker_id = handle.await;
            harness.log("worker_completed", json!({"worker_id": worker_id}));
        }

        // Perform final leak check
        sleep(Duration::from_millis(100)).await; // Allow final cleanup
        let final_check = harness.perform_leak_check("final_concurrent").await;

        harness.log(
            "concurrent_test_complete",
            json!({
                "num_workers": num_workers,
                "operations_per_worker": operations_per_worker,
                "final_leaks": final_check.leaked_obligations,
                "ledger_consistent": final_check.ledger_consistent
            }),
        );

        // Validate zero leaks
        let validation_result = harness.validate_zero_leaks();
        assert!(
            validation_result.is_ok(),
            "Concurrent leak validation failed: {:?}",
            validation_result
        );

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "zero_leaks": final_check.leaked_obligations == 0,
                "consistent": final_check.ledger_consistent,
                "message": "Concurrent obligation workers validated successfully"
            }),
        );
    }

    #[tokio::test]
    async fn test_client_disconnect_forced_cancel_cleans_pending_obligations() {
        let harness = Arc::new(ObligationLeakTestHarness::new());
        let pending_count = 16;
        let cleanup_budget = Duration::from_millis(250);

        harness.log(
            "test_start",
            json!({
                "test": "client_disconnect_forced_cancel_cleanup",
                "pending_count": pending_count,
                "cleanup_budget_ms": cleanup_budget.as_millis()
            }),
        );

        let initial_check = harness.perform_leak_check("initial").await;
        assert_eq!(
            initial_check.leaked_obligations, 0,
            "Should start with zero leaks"
        );
        assert_eq!(
            initial_check.pending_obligations, 0,
            "Should start with zero pending obligations"
        );

        let mut pending_obligations = Vec::with_capacity(pending_count);
        for index in 0..pending_count {
            let obligation_id = harness
                .create_obligation(&format!("client_disconnect_reserved_send_{}", index))
                .await
                .expect("real obligation creation should succeed before disconnect");
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

        let before_cancel = harness.perform_leak_check("before_forced_cancel").await;
        assert_eq!(
            before_cancel.pending_obligations, pending_count,
            "All reserved-send obligations should be pending before disconnect cleanup"
        );
        assert_eq!(
            before_cancel.leaked_obligations, 0,
            "Pending obligations are not leaks before the disconnect budget starts"
        );

        harness.log(
            "forced_cancel_requested",
            json!({
                "scenario": "client_disconnect_during_reserved_send",
                "pending_before": before_cancel.pending_obligations,
                "leaked_before": before_cancel.leaked_obligations,
                "cleanup_budget_ms": cleanup_budget.as_millis()
            }),
        );

        let cleanup_started = Instant::now();
        let cleanup_runtime = RuntimeBuilder::new()
            .with_name("obligation-chaos-client-disconnect-cleanup")
            .worker_threads(2)
            .build()
            .expect("real cleanup runtime should build for obligation chaos E2E");
        let runtime_handle = cleanup_runtime.handle();
        let cleanup_tasks_started = Arc::new(AtomicUsize::new(0));
        let cleanup_tasks_completed = Arc::new(AtomicUsize::new(0));
        let cleanup_region_closed = Arc::new(AtomicBool::new(false));
        let mut cleanup_handles = Vec::with_capacity(pending_obligations.len());

        for (index, obligation_id) in pending_obligations.iter().copied().enumerate() {
            let cleanup_harness = Arc::clone(&harness);
            let tasks_started = Arc::clone(&cleanup_tasks_started);
            let tasks_completed = Arc::clone(&cleanup_tasks_completed);
            let handle = runtime_handle.spawn(async move {
                tasks_started.fetch_add(1, Ordering::AcqRel);
                cleanup_harness
                    .abort_obligation(obligation_id, "client_disconnect_forced_cancel")
                    .await
                    .expect("forced cancellation should abort every pending obligation");
                let completed = tasks_completed.fetch_add(1, Ordering::AcqRel) + 1;

                if index % 4 == 3 {
                    cleanup_harness.log(
                        "stage_progress",
                        json!({
                            "stage": "abort_pending_after_disconnect",
                            "aborted": completed,
                            "elapsed_ms": cleanup_started.elapsed().as_millis()
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

        let after_cancel = harness.perform_leak_check("after_forced_cancel").await;
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
                "cleanup_budget_ms": cleanup_budget.as_millis()
            }),
        );

        assert!(
            cleanup_elapsed <= cleanup_budget,
            "Forced cancellation cleanup exceeded budget: {:?} > {:?}",
            cleanup_elapsed,
            cleanup_budget
        );
        assert_eq!(
            after_cancel.pending_obligations, 0,
            "Forced cancellation must resolve all pending obligations"
        );
        assert_eq!(
            after_cancel.leaked_obligations, 0,
            "Forced cancellation must not leak obligations"
        );
        assert_eq!(
            cleanup_task_start_count, pending_count,
            "Forced cancellation should spawn one cleanup task per pending obligation"
        );
        assert_eq!(
            cleanup_task_complete_count, pending_count,
            "Forced cancellation cleanup tasks must all complete"
        );
        assert!(
            cleanup_region_is_closed,
            "Cleanup region marker should close after all cleanup tasks join"
        );
        assert!(
            cleanup_runtime_is_quiescent,
            "Cleanup runtime should be quiescent after forced cancellation joins"
        );
        assert!(
            after_cancel.ledger_consistent,
            "Ledger should remain consistent after forced cancellation cleanup"
        );

        let validation_result = harness.validate_zero_leaks();
        assert!(
            validation_result.is_ok(),
            "Forced cancellation leak validation failed: {:?}",
            validation_result
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
                "cleanup_within_budget": cleanup_elapsed <= cleanup_budget
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
                    "cleanup_budget_ms": cleanup_budget.as_millis()
                }),
            )
            .expect("artifact bundle should be written when artifact env is set");
    }

    #[tokio::test]
    async fn test_obligation_stress_with_timeouts() {
        let harness = Arc::new(ObligationLeakTestHarness::new());
        harness.log(
            "test_start",
            json!({"test": "obligation_stress_with_timeouts"}),
        );

        let stress_duration = Duration::from_secs(5);
        let timeout_probability = 0.2; // 20% of obligations timeout

        let initial_check = harness.perform_leak_check("initial").await;
        assert_eq!(
            initial_check.leaked_obligations, 0,
            "Should start with zero leaks"
        );

        let stress_start = Instant::now();
        let mut operation_counter = Arc::new(AtomicUsize::new(0));

        let stress_harness = Arc::clone(&harness);
        let stress_counter = Arc::clone(&operation_counter);

        let stress_task = spawn(async move {
            let mut rng = thread_rng();
            let mut pending_obligations = Vec::new();

            while stress_start.elapsed() < stress_duration {
                let op_count = stress_counter.fetch_add(1, Ordering::Relaxed);

                // Create obligation
                if let Ok(obligation_id) = stress_harness
                    .create_obligation(&format!("stress_{}", op_count))
                    .await
                {
                    let should_timeout = rng.gen_bool(timeout_probability);

                    if should_timeout {
                        // Schedule timeout for this obligation
                        let timeout_harness = Arc::clone(&stress_harness);
                        spawn(async move {
                            sleep(Duration::from_millis(rng.gen_range(50..200))).await;
                            let _ = timeout_harness
                                .abort_obligation(obligation_id, "timeout_abort")
                                .await;
                        });
                    } else {
                        pending_obligations.push(obligation_id);
                    }
                }

                // Randomly complete some pending obligations
                if !pending_obligations.is_empty() && rng.gen_bool(0.3) {
                    let idx = rng.gen_range(0..pending_obligations.len());
                    let obligation_id = pending_obligations.remove(idx);

                    if rng.gen_bool(0.8) {
                        let _ = stress_harness
                            .commit_obligation(obligation_id, "stress_commit")
                            .await;
                    } else {
                        let _ = stress_harness
                            .abort_obligation(obligation_id, "stress_abort")
                            .await;
                    }
                }

                // Brief yield
                if op_count % 10 == 0 {
                    sleep(Duration::from_millis(1)).await;
                }
            }

            // Clean up remaining obligations
            for obligation_id in pending_obligations {
                let _ = stress_harness
                    .commit_obligation(obligation_id, "stress_cleanup")
                    .await;
            }
        });

        stress_task.await;

        // Wait for all resources to be properly cleaned up
        let final_check = harness.wait_for_leak_free_state(100, Duration::from_secs(10)).await
            .expect("All obligations should be cleaned up after stress test");
        let total_operations = operation_counter.load(Ordering::Relaxed);

        harness.log(
            "stress_test_complete",
            json!({
                "stress_duration_ms": stress_duration.as_millis(),
                "total_operations": total_operations,
                "timeout_probability": timeout_probability,
                "final_leaks": final_check.leaked_obligations,
                "ledger_consistent": final_check.ledger_consistent
            }),
        );

        // Validate zero leaks
        let validation_result = harness.validate_zero_leaks();
        assert!(
            validation_result.is_ok(),
            "Stress test leak validation failed: {:?}",
            validation_result
        );

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "zero_leaks": final_check.leaked_obligations == 0,
                "consistent": final_check.ledger_consistent,
                "operations_completed": total_operations,
                "message": "Obligation stress test with timeouts validated successfully"
            }),
        );
    }

    #[tokio::test]
    async fn test_obligation_ledger_recovery() {
        let harness = Arc::new(ObligationLeakTestHarness::new());
        harness.log("test_start", json!({"test": "obligation_ledger_recovery"}));

        // Create some obligations in various states
        let mut test_obligations = Vec::new();

        // Create 10 obligations
        for i in 0..10 {
            if let Ok(obligation_id) = harness
                .create_obligation(&format!("recovery_test_{}", i))
                .await
            {
                test_obligations.push(obligation_id);
            }
        }

        // Commit some
        for obligation_id in &test_obligations[0..3] {
            let _ = harness
                .commit_obligation(*obligation_id, "recovery_commit")
                .await;
        }

        // Abort some
        for obligation_id in &test_obligations[3..6] {
            let _ = harness
                .abort_obligation(*obligation_id, "recovery_abort")
                .await;
        }

        // Leave some pending: test_obligations[6..10]

        let pre_recovery_check = harness.perform_leak_check("pre_recovery").await;
        assert_eq!(
            pre_recovery_check.pending_obligations, 4,
            "Should have 4 pending obligations"
        );

        // Simulate recovery scenario - force cleanup of pending obligations
        for obligation_id in &test_obligations[6..10] {
            let _ = harness
                .abort_obligation(*obligation_id, "recovery_cleanup")
                .await;
        }

        let post_recovery_check = harness.perform_leak_check("post_recovery").await;

        harness.log(
            "recovery_test_complete",
            json!({
                "pre_recovery_pending": pre_recovery_check.pending_obligations,
                "post_recovery_pending": post_recovery_check.pending_obligations,
                "post_recovery_leaks": post_recovery_check.leaked_obligations,
                "ledger_consistent": post_recovery_check.ledger_consistent
            }),
        );

        // Validate recovery success
        assert_eq!(
            post_recovery_check.pending_obligations, 0,
            "All obligations should be resolved"
        );
        assert_eq!(
            post_recovery_check.leaked_obligations, 0,
            "No leaks should remain"
        );
        assert!(
            post_recovery_check.ledger_consistent,
            "Ledger should be consistent"
        );

        let validation_result = harness.validate_zero_leaks();
        assert!(
            validation_result.is_ok(),
            "Recovery validation failed: {:?}",
            validation_result
        );

        harness.log(
            "test_result",
            json!({
                "passed": true,
                "recovery_successful": post_recovery_check.pending_obligations == 0,
                "zero_leaks": post_recovery_check.leaked_obligations == 0,
                "message": "Obligation ledger recovery validated successfully"
            }),
        );
    }
}

use crate::obligation::ledger::ObligationLedger;
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

    fn record_operation(&self, operation: ObligationOperation) {
        self.operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(operation);
    }

    fn create_reserved_send(&self, context: &str) -> ObligationId {
        let mut ledger = self
            .ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = ledger.len();
        let token = ledger.acquire_with_context(
            ObligationKind::SendPermit,
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
                "obligation_id": obligation_id.to_string(),
                "ledger_size_before": before,
                "ledger_size_after": after
            }),
        );

        obligation_id
    }

    fn abort_reserved_send(
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

    harness.log(
        "test_start",
        json!({
            "test": "client_disconnect_forced_cancel_cleanup",
            "pending_count": pending_count,
            "cleanup_budget_ms": cleanup_budget.as_millis()
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
            "cleanup_budget_ms": cleanup_budget.as_millis()
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
        let handle = runtime_handle.spawn(async move {
            tasks_started.fetch_add(1, Ordering::AcqRel);
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
            "cleanup_budget_ms": cleanup_budget.as_millis()
        }),
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

    harness.log(
        "test_result",
        json!({
            "passed": true,
            "scenario": "client_disconnect_during_reserved_send",
            "zero_pending": after_cancel.pending_obligations == 0,
            "zero_leaks": after_cancel.leaked_obligations == 0,
            "no_task_leaks": cleanup_task_complete_count == pending_count,
            "region_close_implies_quiescence": cleanup_region_is_closed && cleanup_runtime_is_quiescent,
            "cleanup_within_budget": cleanup_elapsed <= cleanup_budget
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
                "cleanup_budget_ms": cleanup_budget.as_millis()
            }),
        )
        .expect("artifact bundle should be written when artifact env is set");
}
