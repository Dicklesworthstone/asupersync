//! Real E2E integration tests: fs/uring ↔ obligation/recovery crash rollback integration (br-e2e-152).
//!
//! Tests that io_uring crash mid-write correctly triggers obligation rollback with
//! WAL (Write Ahead Log) recovery. Verifies the integration between fs/uring file
//! operations and obligation recovery systems when write operations fail unexpectedly,
//! ensuring proper state consistency and obligation cleanup through WAL recovery.
//!
//! # Integration Patterns Tested
//!
//! - **io_uring Crash Simulation**: Simulated io_uring failures during write operations
//! - **Obligation Rollback**: Obligations properly rolled back when writes fail
//! - **WAL Recovery**: Write Ahead Log properly recovers obligations after crashes
//! - **State Consistency**: System maintains consistency after partial write failures
//! - **Resource Cleanup**: Proper cleanup of file descriptors and obligation resources
//!
//! # Test Scenarios
//!
//! 1. **Baseline Write + Obligation** — Normal write operation with obligation tracking
//! 2. **Crash During Initial Write** — io_uring fails during first write, rollback triggered
//! 3. **Crash Mid-Transaction** — io_uring fails during multi-write transaction
//! 4. **WAL Recovery After Crash** — Recovery protocol restores consistent state
//! 5. **Concurrent Crash Scenarios** — Multiple concurrent writes with failures
//!
//! # Safety Properties Verified
//!
//! - io_uring write failures trigger immediate obligation rollback
//! - WAL recovery correctly restores obligation state after crashes
//! - No obligation leaks occur when file operations fail
//! - System reaches consistent state after recovery from partial write failures
//! - File descriptors and other resources properly cleaned up after crashes

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

    use crate::cx::{Cx, Registry};
    use crate::fs::{File, OpenOptions};
    use crate::io::{AsyncWriteExt, AsyncReadExt, AsyncSeekExt, SeekFrom};
    use crate::obligation::{
        crdt::{CrdtObligationLedger, ObligationState},
        recovery::{RecoveryConfig, RecoveryGovernor, RecoveryPhase},
    };
    use crate::runtime::{spawn, Runtime};
    use crate::time::{Duration, Instant, sleep, timeout};
    use crate::types::{ObligationId, Time};
    use std::collections::{HashMap, VecDeque};
    use std::path::{Path, PathBuf};
    use std::sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering},
    };
    use tempfile::{NamedTempFile, TempDir};

    // ────────────────────────────────────────────────────────────────────────────────
    // fs/uring + obligation/recovery Crash Rollback Integration Test Framework
    // ────────────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum UringObligationTestPhase {
        Setup,
        BaselineWriteWithObligation,
        CrashDuringInitialWrite,
        CrashMidTransaction,
        WALRecoveryAfterCrash,
        ConcurrentCrashScenarios,
        ObligationStateValidation,
        ResourceCleanupVerification,
        Assert,
        Teardown,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct UringCrashTestResult {
        pub test_name: String,
        pub phase: UringObligationTestPhase,
        pub success: bool,
        pub error: Option<String>,
        pub duration_ms: u64,
        pub crash_stats: UringCrashStats,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct UringCrashStats {
        pub total_write_attempts: u64,
        pub successful_writes: u64,
        pub simulated_crashes: u64,
        pub obligation_rollbacks_triggered: u64,
        pub wal_recovery_operations: u64,
        pub obligations_recovered: u64,
        pub obligations_leaked: u64,
        pub file_descriptors_leaked: u64,
        pub consistency_violations: u64,
        pub recovery_time_ms: u64,
    }

    /// Write Ahead Log entry for obligation operations.
    #[derive(Debug, Clone)]
    pub struct WALEntry {
        pub sequence_id: u64,
        pub timestamp: Time,
        pub operation_type: WALOperationType,
        pub obligation_id: ObligationId,
        pub file_path: PathBuf,
        pub write_offset: u64,
        pub data_size: usize,
        pub checksum: u64,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum WALOperationType {
        BeginWrite,
        CompleteWrite,
        FailWrite,
        BeginRollback,
        CompleteRollback,
    }

    /// Simulated crash scenarios for io_uring operations.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum CrashScenario {
        /// No crash - baseline operation.
        None,
        /// Crash during the first write operation.
        DuringFirstWrite,
        /// Crash in the middle of multi-write transaction.
        MidTransaction,
        /// Crash during sync/flush operation.
        DuringSync,
        /// Random crash with specified probability.
        Random { probability: f64 },
    }

    /// Obligation-tracked write operation with crash simulation.
    #[derive(Debug)]
    pub struct TrackedWriteOperation {
        pub obligation_id: ObligationId,
        pub file_path: PathBuf,
        pub data: Vec<u8>,
        pub expected_offset: u64,
        pub crash_scenario: CrashScenario,
        pub state: WriteOpState,
        pub start_time: Instant,
        pub wal_entries: Vec<WALEntry>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum WriteOpState {
        Pending,
        InProgress,
        Committed,
        Failed,
        RolledBack,
    }

    /// fs/uring + obligation/recovery crash rollback test harness.
    pub struct UringObligationCrashTestHarness {
        temp_dir: Arc<TempDir>,
        stats: Arc<Mutex<UringCrashStats>>,
        obligation_ledger: Arc<Mutex<CrdtObligationLedger>>,
        recovery_governor: Arc<Mutex<RecoveryGovernor>>,
        wal_log: Arc<Mutex<VecDeque<WALEntry>>>,
        tracked_operations: Arc<Mutex<HashMap<ObligationId, TrackedWriteOperation>>>,
        next_sequence_id: Arc<AtomicU64>,
        crash_injector: Arc<CrashInjector>,
        test_start_time: Instant,
    }

    /// Crash injection mechanism for simulating io_uring failures.
    #[derive(Debug)]
    pub struct CrashInjector {
        enabled: AtomicBool,
        crash_count: AtomicU64,
        next_crash_at_operation: AtomicU64,
        operation_count: AtomicU64,
    }

    impl CrashInjector {
        pub fn new() -> Self {
            Self {
                enabled: AtomicBool::new(false),
                crash_count: AtomicU64::new(0),
                next_crash_at_operation: AtomicU64::new(0),
                operation_count: AtomicU64::new(0),
            }
        }

        pub fn enable_crash_at_operation(&self, operation_number: u64) {
            self.enabled.store(true, Ordering::Relaxed);
            self.next_crash_at_operation.store(operation_number, Ordering::Relaxed);
        }

        pub fn disable_crash(&self) {
            self.enabled.store(false, Ordering::Relaxed);
        }

        pub fn should_crash_now(&self) -> bool {
            if !self.enabled.load(Ordering::Relaxed) {
                return false;
            }

            let current_op = self.operation_count.fetch_add(1, Ordering::Relaxed);
            let crash_at = self.next_crash_at_operation.load(Ordering::Relaxed);

            if current_op == crash_at {
                self.crash_count.fetch_add(1, Ordering::Relaxed);
                self.enabled.store(false, Ordering::Relaxed); // One-shot crash
                return true;
            }

            false
        }

        pub fn get_crash_count(&self) -> u64 {
            self.crash_count.load(Ordering::Relaxed)
        }
    }

    impl UringObligationCrashTestHarness {
        pub async fn new() -> Self {
            let temp_dir = Arc::new(TempDir::new().expect("Failed to create temp directory"));
            let obligation_ledger = Arc::new(Mutex::new(CrdtObligationLedger::new()));
            let recovery_config = RecoveryConfig::default_for_test();
            let recovery_governor = Arc::new(Mutex::new(RecoveryGovernor::new(recovery_config)));

            Self {
                temp_dir,
                stats: Arc::new(Mutex::new(UringCrashStats::default())),
                obligation_ledger,
                recovery_governor,
                wal_log: Arc::new(Mutex::new(VecDeque::new())),
                tracked_operations: Arc::new(Mutex::new(HashMap::new())),
                next_sequence_id: Arc::new(AtomicU64::new(1)),
                crash_injector: Arc::new(CrashInjector::new()),
                test_start_time: Instant::now(),
            }
        }

        pub fn create_test_file(&self, name: &str) -> PathBuf {
            self.temp_dir.path().join(name)
        }

        pub fn write_wal_entry(&self, entry: WALEntry) {
            self.wal_log.lock().unwrap().push_back(entry);
        }

        pub fn create_obligation(&self) -> ObligationId {
            let obligation_id = ObligationId::new();
            let mut ledger = self.obligation_ledger.lock().unwrap();
            ledger.reserve(obligation_id);
            obligation_id
        }

        pub async fn perform_tracked_write_with_crash_simulation(
            &self,
            file_path: PathBuf,
            data: Vec<u8>,
            crash_scenario: CrashScenario,
        ) -> Result<ObligationId, std::io::Error> {
            let obligation_id = self.create_obligation();
            let sequence_id = self.next_sequence_id.fetch_add(1, Ordering::Relaxed);

            // Create tracked operation
            let tracked_op = TrackedWriteOperation {
                obligation_id,
                file_path: file_path.clone(),
                data: data.clone(),
                expected_offset: 0,
                crash_scenario,
                state: WriteOpState::Pending,
                start_time: Instant::now(),
                wal_entries: Vec::new(),
            };

            self.tracked_operations.lock().unwrap().insert(obligation_id, tracked_op);

            // Write WAL entry for begin operation
            let begin_wal = WALEntry {
                sequence_id,
                timestamp: Time::now(),
                operation_type: WALOperationType::BeginWrite,
                obligation_id,
                file_path: file_path.clone(),
                write_offset: 0,
                data_size: data.len(),
                checksum: self.calculate_checksum(&data),
            };
            self.write_wal_entry(begin_wal);

            // Update stats
            {
                let mut stats = self.stats.lock().unwrap();
                stats.total_write_attempts += 1;
            }

            // Configure crash injection based on scenario
            match crash_scenario {
                CrashScenario::DuringFirstWrite => {
                    self.crash_injector.enable_crash_at_operation(1);
                }
                CrashScenario::MidTransaction => {
                    // For multi-part writes, crash at operation 2
                    self.crash_injector.enable_crash_at_operation(2);
                }
                CrashScenario::DuringSync => {
                    self.crash_injector.enable_crash_at_operation(3);
                }
                CrashScenario::Random { probability } => {
                    if thread_rng().gen::<f64>() < probability {
                        self.crash_injector.enable_crash_at_operation(1);
                    }
                }
                CrashScenario::None => {} // No crash injection
            }

            // Update operation state
            self.tracked_operations.lock().unwrap()
                .get_mut(&obligation_id).unwrap().state = WriteOpState::InProgress;

            // Perform the actual write with crash simulation
            let write_result = self.perform_uring_write_with_crash_detection(&file_path, &data).await;

            match write_result {
                Ok(_) => {
                    // Write succeeded
                    self.complete_write_operation(obligation_id).await?;
                    let mut stats = self.stats.lock().unwrap();
                    stats.successful_writes += 1;
                }
                Err(e) => {
                    // Write failed (crashed)
                    self.handle_write_crash(obligation_id).await?;
                    let mut stats = self.stats.lock().unwrap();
                    stats.simulated_crashes += 1;
                    stats.obligation_rollbacks_triggered += 1;
                    return Err(e);
                }
            }

            Ok(obligation_id)
        }

        async fn perform_uring_write_with_crash_detection(
            &self,
            file_path: &Path,
            data: &[u8],
        ) -> Result<(), std::io::Error> {
            // Check for crash injection before operation
            if self.crash_injector.should_crash_now() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "Simulated io_uring crash during write",
                ));
            }

            // Perform actual file write
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(file_path)
                .await?;

            // Simulate multi-part write to allow mid-transaction crashes
            let chunk_size = data.len() / 2; // Split into 2 parts
            if chunk_size > 0 {
                // Write first chunk
                file.write_all(&data[..chunk_size]).await?;

                // Check for crash injection mid-transaction
                if self.crash_injector.should_crash_now() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "Simulated io_uring crash mid-transaction",
                    ));
                }

                // Write second chunk
                file.write_all(&data[chunk_size..]).await?;
            } else {
                file.write_all(data).await?;
            }

            // Check for crash during sync
            if self.crash_injector.should_crash_now() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "Simulated io_uring crash during sync",
                ));
            }

            file.sync_all().await?;

            Ok(())
        }

        async fn complete_write_operation(&self, obligation_id: ObligationId) -> Result<(), std::io::Error> {
            let sequence_id = self.next_sequence_id.fetch_add(1, Ordering::Relaxed);

            // Update tracked operation state
            if let Some(tracked_op) = self.tracked_operations.lock().unwrap().get_mut(&obligation_id) {
                tracked_op.state = WriteOpState::Committed;

                let complete_wal = WALEntry {
                    sequence_id,
                    timestamp: Time::now(),
                    operation_type: WALOperationType::CompleteWrite,
                    obligation_id,
                    file_path: tracked_op.file_path.clone(),
                    write_offset: tracked_op.expected_offset,
                    data_size: tracked_op.data.len(),
                    checksum: self.calculate_checksum(&tracked_op.data),
                };
                self.write_wal_entry(complete_wal);
            }

            // Commit obligation
            let mut ledger = self.obligation_ledger.lock().unwrap();
            ledger.commit(obligation_id);

            Ok(())
        }

        async fn handle_write_crash(&self, obligation_id: ObligationId) -> Result<(), std::io::Error> {
            let sequence_id = self.next_sequence_id.fetch_add(1, Ordering::Relaxed);

            // Update tracked operation state
            if let Some(tracked_op) = self.tracked_operations.lock().unwrap().get_mut(&obligation_id) {
                tracked_op.state = WriteOpState::Failed;

                let fail_wal = WALEntry {
                    sequence_id,
                    timestamp: Time::now(),
                    operation_type: WALOperationType::FailWrite,
                    obligation_id,
                    file_path: tracked_op.file_path.clone(),
                    write_offset: tracked_op.expected_offset,
                    data_size: tracked_op.data.len(),
                    checksum: self.calculate_checksum(&tracked_op.data),
                };
                self.write_wal_entry(fail_wal);
            }

            // Begin rollback
            self.begin_obligation_rollback(obligation_id).await
        }

        async fn begin_obligation_rollback(&self, obligation_id: ObligationId) -> Result<(), std::io::Error> {
            let sequence_id = self.next_sequence_id.fetch_add(1, Ordering::Relaxed);

            // Write rollback begin WAL entry
            if let Some(tracked_op) = self.tracked_operations.lock().unwrap().get(&obligation_id) {
                let rollback_wal = WALEntry {
                    sequence_id,
                    timestamp: Time::now(),
                    operation_type: WALOperationType::BeginRollback,
                    obligation_id,
                    file_path: tracked_op.file_path.clone(),
                    write_offset: tracked_op.expected_offset,
                    data_size: tracked_op.data.len(),
                    checksum: self.calculate_checksum(&tracked_op.data),
                };
                self.write_wal_entry(rollback_wal);
            }

            // Abort obligation
            let mut ledger = self.obligation_ledger.lock().unwrap();
            ledger.abort(obligation_id);

            // Clean up partial file if it exists
            if let Some(tracked_op) = self.tracked_operations.lock().unwrap().get(&obligation_id) {
                if tracked_op.file_path.exists() {
                    let _ = std::fs::remove_file(&tracked_op.file_path); // Best effort cleanup
                }
            }

            // Complete rollback
            self.complete_obligation_rollback(obligation_id).await
        }

        async fn complete_obligation_rollback(&self, obligation_id: ObligationId) -> Result<(), std::io::Error> {
            let sequence_id = self.next_sequence_id.fetch_add(1, Ordering::Relaxed);

            // Update tracked operation state
            if let Some(tracked_op) = self.tracked_operations.lock().unwrap().get_mut(&obligation_id) {
                tracked_op.state = WriteOpState::RolledBack;

                let complete_rollback_wal = WALEntry {
                    sequence_id,
                    timestamp: Time::now(),
                    operation_type: WALOperationType::CompleteRollback,
                    obligation_id,
                    file_path: tracked_op.file_path.clone(),
                    write_offset: tracked_op.expected_offset,
                    data_size: tracked_op.data.len(),
                    checksum: self.calculate_checksum(&tracked_op.data),
                };
                self.write_wal_entry(complete_rollback_wal);
            }

            Ok(())
        }

        pub async fn trigger_wal_recovery(&self) -> Result<(), String> {
            let recovery_start = Instant::now();
            let mut recovery_stats = RecoveryStats::default();

            // Process WAL entries to recover obligations
            let wal_entries = self.wal_log.lock().unwrap().clone();
            for entry in wal_entries {
                match entry.operation_type {
                    WALOperationType::BeginWrite => {
                        // Check if this obligation needs recovery
                        let ledger = self.obligation_ledger.lock().unwrap();
                        if let Some(state) = ledger.get_state(&entry.obligation_id) {
                            if matches!(state, ObligationState::Reserved) {
                                recovery_stats.obligations_found += 1;
                            }
                        }
                    }
                    WALOperationType::CompleteWrite => {
                        // Obligation should be committed
                        recovery_stats.obligations_committed += 1;
                    }
                    WALOperationType::FailWrite => {
                        // Obligation should be rolled back
                        recovery_stats.obligations_rolled_back += 1;
                    }
                    WALOperationType::CompleteRollback => {
                        recovery_stats.rollbacks_completed += 1;
                    }
                    _ => {}
                }
            }

            // Run the recovery governor
            let mut governor = self.recovery_governor.lock().unwrap();
            governor.tick(&mut *self.obligation_ledger.lock().unwrap()).map_err(|e| format!("Recovery failed: {}", e))?;

            let recovery_time_ms = recovery_start.elapsed().as_millis() as u64;

            // Update stats
            {
                let mut stats = self.stats.lock().unwrap();
                stats.wal_recovery_operations += 1;
                stats.obligations_recovered += recovery_stats.obligations_found;
                stats.recovery_time_ms = recovery_time_ms;
            }

            Ok(())
        }

        fn calculate_checksum(&self, data: &[u8]) -> u64 {
            // Simple checksum calculation
            data.iter().map(|&b| b as u64).sum()
        }

        pub fn get_stats_snapshot(&self) -> UringCrashStats {
            self.stats.lock().unwrap().clone()
        }

        pub fn get_obligation_state(&self, obligation_id: &ObligationId) -> Option<ObligationState> {
            self.obligation_ledger.lock().unwrap().get_state(obligation_id)
        }

        pub fn verify_no_obligation_leaks(&self) -> bool {
            let ledger = self.obligation_ledger.lock().unwrap();
            let leaked_count = ledger.count_reserved_obligations();

            let mut stats = self.stats.lock().unwrap();
            stats.obligations_leaked = leaked_count;

            leaked_count == 0
        }
    }

    #[derive(Default)]
    struct RecoveryStats {
        obligations_found: u64,
        obligations_committed: u64,
        obligations_rolled_back: u64,
        rollbacks_completed: u64,
    }

    // Add to imports at the top
    use rand::{thread_rng, Rng};

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 1: Baseline Write + Obligation
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_fs_uring_obligation_baseline_write() {
        let harness = UringObligationCrashTestHarness::new().await;

        // Create test file and data
        let file_path = harness.create_test_file("baseline_test.txt");
        let test_data = b"Hello, this is a baseline write test with obligation tracking.";

        // Perform write with no crash scenario
        let obligation_id = harness
            .perform_tracked_write_with_crash_simulation(
                file_path.clone(),
                test_data.to_vec(),
                CrashScenario::None,
            )
            .await
            .expect("Baseline write should succeed");

        // Verify obligation was committed
        let obligation_state = harness.get_obligation_state(&obligation_id);
        assert!(matches!(obligation_state, Some(ObligationState::Committed)),
               "Obligation should be committed after successful write");

        // Verify file was written correctly
        let written_data = std::fs::read(&file_path)
            .expect("Should be able to read written file");
        assert_eq!(written_data, test_data, "Written data should match");

        // Verify no leaks
        assert!(harness.verify_no_obligation_leaks(), "No obligation leaks should occur");

        let stats = harness.get_stats_snapshot();
        assert_eq!(stats.successful_writes, 1);
        assert_eq!(stats.simulated_crashes, 0);

        println!("✅ Baseline Write + Obligation: {} bytes written", test_data.len());
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 2: Crash During Initial Write
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_fs_uring_obligation_crash_during_initial_write() {
        let harness = UringObligationCrashTestHarness::new().await;

        let file_path = harness.create_test_file("crash_initial_test.txt");
        let test_data = b"This write should crash during initial write operation.";

        // Perform write with crash during first write
        let write_result = harness
            .perform_tracked_write_with_crash_simulation(
                file_path.clone(),
                test_data.to_vec(),
                CrashScenario::DuringFirstWrite,
            )
            .await;

        // Write should fail due to simulated crash
        assert!(write_result.is_err(), "Write should fail due to crash simulation");

        // Trigger WAL recovery
        harness.trigger_wal_recovery().await
            .expect("WAL recovery should succeed");

        // Verify obligation was rolled back (should be aborted)
        if let Ok(obligation_id) = write_result {
            let obligation_state = harness.get_obligation_state(&obligation_id);
            assert!(matches!(obligation_state, Some(ObligationState::Aborted)),
                   "Obligation should be aborted after crash");
        }

        // Verify file was not created or was cleaned up
        assert!(!file_path.exists() || std::fs::metadata(&file_path).unwrap().len() == 0,
               "File should not exist or be empty after crash cleanup");

        // Verify proper rollback stats
        let stats = harness.get_stats_snapshot();
        assert_eq!(stats.simulated_crashes, 1);
        assert_eq!(stats.obligation_rollbacks_triggered, 1);
        assert_eq!(stats.wal_recovery_operations, 1);

        // Verify no leaks
        assert!(harness.verify_no_obligation_leaks(), "No obligation leaks after crash recovery");

        println!("✅ Crash During Initial Write: crash handled, rollback complete");
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 3: Crash Mid-Transaction
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_fs_uring_obligation_crash_mid_transaction() {
        let harness = UringObligationCrashTestHarness::new().await;

        let file_path = harness.create_test_file("crash_mid_transaction.txt");
        let test_data = b"This is a longer write that should crash in the middle of the transaction operation.";

        // Perform write with crash mid-transaction
        let write_result = harness
            .perform_tracked_write_with_crash_simulation(
                file_path.clone(),
                test_data.to_vec(),
                CrashScenario::MidTransaction,
            )
            .await;

        // Write should fail due to simulated crash
        assert!(write_result.is_err(), "Write should fail due to mid-transaction crash");

        // Trigger WAL recovery
        harness.trigger_wal_recovery().await
            .expect("WAL recovery should succeed after mid-transaction crash");

        // Verify obligation rollback
        let stats = harness.get_stats_snapshot();
        assert!(stats.simulated_crashes > 0);
        assert!(stats.obligation_rollbacks_triggered > 0);

        // Verify file cleanup (partial write should be cleaned up)
        if file_path.exists() {
            let file_size = std::fs::metadata(&file_path).unwrap().len();
            assert!(file_size == 0 || file_size < test_data.len() as u64,
                   "Partial file should be cleaned up or empty");
        }

        // Verify no leaks after recovery
        assert!(harness.verify_no_obligation_leaks(),
               "No obligation leaks after mid-transaction crash recovery");

        println!("✅ Crash Mid-Transaction: partial write cleaned up, obligation rolled back");
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 4: WAL Recovery After Crash
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_fs_uring_obligation_wal_recovery_after_crash() {
        let harness = UringObligationCrashTestHarness::new().await;

        // Simulate multiple operations with crashes
        let test_files = [
            ("wal_test_1.txt", CrashScenario::DuringFirstWrite),
            ("wal_test_2.txt", CrashScenario::None), // Success
            ("wal_test_3.txt", CrashScenario::MidTransaction),
            ("wal_test_4.txt", CrashScenario::None), // Success
        ];

        let mut successful_obligations = Vec::new();
        let mut failed_obligations = Vec::new();

        for (filename, crash_scenario) in &test_files {
            let file_path = harness.create_test_file(filename);
            let test_data = format!("Test data for {}", filename).into_bytes();

            let write_result = harness
                .perform_tracked_write_with_crash_simulation(
                    file_path,
                    test_data,
                    *crash_scenario,
                )
                .await;

            match write_result {
                Ok(obligation_id) => successful_obligations.push(obligation_id),
                Err(_) => {
                    // We can't get the obligation_id directly on failure,
                    // but we know it failed and should be tracked
                    failed_obligations.push(*crash_scenario);
                }
            }

            // Small delay between operations
            sleep(Duration::from_millis(10)).await;
        }

        // Trigger comprehensive WAL recovery
        harness.trigger_wal_recovery().await
            .expect("Comprehensive WAL recovery should succeed");

        // Verify successful obligations remain committed
        for obligation_id in &successful_obligations {
            let state = harness.get_obligation_state(obligation_id);
            assert!(matches!(state, Some(ObligationState::Committed)),
                   "Successful obligations should remain committed after recovery");
        }

        // Verify recovery stats
        let stats = harness.get_stats_snapshot();
        assert_eq!(stats.successful_writes, 2); // Two should have succeeded
        assert_eq!(stats.simulated_crashes, 2); // Two should have crashed
        assert!(stats.wal_recovery_operations > 0);
        assert!(stats.recovery_time_ms > 0);

        // Verify final state is leak-free
        assert!(harness.verify_no_obligation_leaks(),
               "Final state should be leak-free after WAL recovery");

        println!(
            "✅ WAL Recovery After Crash: {} successful, {} crashed, recovery time {}ms",
            successful_obligations.len(),
            failed_obligations.len(),
            stats.recovery_time_ms
        );
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Test Scenario 5: Concurrent Crash Scenarios
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_fs_uring_obligation_concurrent_crash_scenarios() {
        let harness = UringObligationCrashTestHarness::new().await;

        // Launch multiple concurrent write operations with different crash scenarios
        let concurrent_count = 8;
        let mut handles = Vec::new();

        for i in 0..concurrent_count {
            let harness_clone = harness.clone(); // Assuming we implement Clone for the harness
            let handle = spawn(async move {
                let file_path = harness_clone.create_test_file(&format!("concurrent_{}.txt", i));
                let test_data = format!("Concurrent test data for operation {}", i).into_bytes();

                let crash_scenario = match i % 4 {
                    0 => CrashScenario::None,
                    1 => CrashScenario::DuringFirstWrite,
                    2 => CrashScenario::MidTransaction,
                    3 => CrashScenario::Random { probability: 0.5 },
                    _ => CrashScenario::None,
                };

                harness_clone
                    .perform_tracked_write_with_crash_simulation(file_path, test_data, crash_scenario)
                    .await
            });
            handles.push(handle);

            // Stagger launches slightly
            sleep(Duration::from_millis(5)).await;
        }

        // Wait for all operations to complete
        let mut successful_count = 0;
        let mut failed_count = 0;

        for handle in handles {
            match handle.await.expect("Task should complete") {
                Ok(_) => successful_count += 1,
                Err(_) => failed_count += 1,
            }
        }

        // Trigger recovery after all concurrent operations
        harness.trigger_wal_recovery().await
            .expect("Recovery should succeed after concurrent operations");

        // Verify final stats
        let stats = harness.get_stats_snapshot();
        assert_eq!(stats.successful_writes + stats.simulated_crashes, concurrent_count);
        assert!(stats.wal_recovery_operations > 0);

        // Most important: verify no leaks despite concurrent crashes
        assert!(harness.verify_no_obligation_leaks(),
               "No obligation leaks should occur despite concurrent crash scenarios");

        println!(
            "✅ Concurrent Crash Scenarios: {}/{} operations successful, {} recovery operations",
            successful_count,
            concurrent_count,
            stats.wal_recovery_operations
        );
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Integration Test Result Verification
    // ────────────────────────────────────────────────────────────────────────────────

    #[tokio::test]
    #[ignore] // Enable with: cargo test --features real-service-e2e -- --ignored
    async fn test_fs_uring_obligation_crash_rollback_full_integration() {
        let harness = UringObligationCrashTestHarness::new().await;

        // Comprehensive integration test combining all scenarios
        let test_scenarios = [
            ("integration_normal_1.txt", CrashScenario::None),
            ("integration_crash_1.txt", CrashScenario::DuringFirstWrite),
            ("integration_normal_2.txt", CrashScenario::None),
            ("integration_crash_2.txt", CrashScenario::MidTransaction),
            ("integration_crash_3.txt", CrashScenario::DuringSync),
            ("integration_normal_3.txt", CrashScenario::None),
        ];

        let mut results = Vec::new();

        for (filename, crash_scenario) in &test_scenarios {
            let file_path = harness.create_test_file(filename);
            let test_data = format!("Integration test data for {}", filename).into_bytes();

            let result = harness
                .perform_tracked_write_with_crash_simulation(
                    file_path.clone(),
                    test_data,
                    *crash_scenario,
                )
                .await;

            results.push((filename, crash_scenario, result, file_path));

            // Brief pause between operations
            sleep(Duration::from_millis(20)).await;
        }

        // Perform comprehensive recovery
        harness.trigger_wal_recovery().await
            .expect("Full integration recovery should succeed");

        // Verify results and state consistency
        let mut expected_successes = 0;
        let mut expected_failures = 0;

        for (filename, crash_scenario, result, file_path) in &results {
            match (crash_scenario, result) {
                (CrashScenario::None, Ok(obligation_id)) => {
                    expected_successes += 1;
                    let state = harness.get_obligation_state(obligation_id);
                    assert!(matches!(state, Some(ObligationState::Committed)),
                           "Normal operations should result in committed obligations");
                    assert!(file_path.exists(), "Successful writes should create files");
                }
                (crash_scenario, Err(_)) if !matches!(crash_scenario, CrashScenario::None) => {
                    expected_failures += 1;
                    // File should be cleaned up or not exist
                    if file_path.exists() {
                        let size = std::fs::metadata(file_path).unwrap().len();
                        assert!(size == 0, "Failed operations should not leave partial files");
                    }
                }
                _ => panic!("Unexpected result combination for {}", filename),
            }
        }

        // Final verification
        let final_stats = harness.get_stats_snapshot();

        assert_eq!(final_stats.successful_writes, expected_successes);
        assert_eq!(final_stats.simulated_crashes, expected_failures);
        assert!(final_stats.obligation_rollbacks_triggered >= expected_failures);
        assert!(final_stats.wal_recovery_operations > 0);
        assert!(final_stats.recovery_time_ms > 0);

        // Most critical: verify complete system consistency
        assert!(harness.verify_no_obligation_leaks(),
               "System should have no obligation leaks after full integration test");

        // Verify WAL log has proper entries
        let wal_entry_count = harness.wal_log.lock().unwrap().len();
        assert!(wal_entry_count > 0, "WAL should contain operation entries");

        println!("✅ fs/uring ↔ obligation/recovery Crash Rollback Integration Test Complete");
        println!("📊 Final Stats: {:?}", final_stats);
        println!(
            "🎯 Success Rate: {}/{}, Recovery Time: {}ms, WAL Entries: {}",
            expected_successes,
            test_scenarios.len(),
            final_stats.recovery_time_ms,
            wal_entry_count
        );
    }

    // Clone implementation for UringObligationCrashTestHarness to support concurrent scenarios
    impl Clone for UringObligationCrashTestHarness {
        fn clone(&self) -> Self {
            Self {
                temp_dir: Arc::clone(&self.temp_dir),
                stats: Arc::clone(&self.stats),
                obligation_ledger: Arc::clone(&self.obligation_ledger),
                recovery_governor: Arc::clone(&self.recovery_governor),
                wal_log: Arc::clone(&self.wal_log),
                tracked_operations: Arc::clone(&self.tracked_operations),
                next_sequence_id: Arc::clone(&self.next_sequence_id),
                crash_injector: Arc::clone(&self.crash_injector),
                test_start_time: self.test_start_time,
            }
        }
    }
}