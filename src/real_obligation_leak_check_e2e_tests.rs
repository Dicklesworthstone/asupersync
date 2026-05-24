//! Real obligation/leak_check E2E tests
//!
//! Tests obligation ledger with random spawn/abort sequences to validate
//! zero leaks. Uses real asupersync obligation tracking with comprehensive
//! leak detection and ledger state validation.

#[cfg(all(test, feature = "real-service-e2e"))]
mod real_obligation_leak_check_e2e {
    use crate::cx::{Cx, scope};
    use crate::obligation::{LeakCheckResult, ObligationId, ObligationLedger, ObligationState};
    use crate::runtime::{Runtime, spawn};
    use crate::time::{Duration, Instant, sleep};
    use crate::types::{Budget, Outcome};
    use rand::{Rng, seq::SliceRandom, thread_rng};
    use serde_json::{Value, json};
    use std::collections::{HashMap, HashSet};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

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
        for (index, obligation_id) in pending_obligations.iter().copied().enumerate() {
            harness
                .abort_obligation(obligation_id, "client_disconnect_forced_cancel")
                .await
                .expect("forced cancellation should abort every pending obligation");

            if index % 4 == 3 {
                harness.log(
                    "stage_progress",
                    json!({
                        "stage": "abort_pending_after_disconnect",
                        "aborted": index + 1,
                        "elapsed_ms": cleanup_started.elapsed().as_millis()
                    }),
                );
            }
        }
        let cleanup_elapsed = cleanup_started.elapsed();

        let after_cancel = harness.perform_leak_check("after_forced_cancel").await;
        harness.log(
            "forced_cancel_cleanup_complete",
            json!({
                "pending_before": before_cancel.pending_obligations,
                "pending_after": after_cancel.pending_obligations,
                "leaked_after": after_cancel.leaked_obligations,
                "ledger_consistent": after_cancel.ledger_consistent,
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
                "cleanup_within_budget": cleanup_elapsed <= cleanup_budget
            }),
        );
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

        // Wait for timeouts to complete
        sleep(Duration::from_millis(500)).await;

        // Perform final leak check
        let final_check = harness.perform_leak_check("final_stress").await;
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
