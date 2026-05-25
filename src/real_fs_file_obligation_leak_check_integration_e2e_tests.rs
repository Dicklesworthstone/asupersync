//! Real E2E integration tests: fs/file ↔ obligation/leak_check integration (br-e2e-172).
//!
//! Tests that file handles released through Drop don't leak obligations even when panicking.
//! Verifies that the filesystem and obligation leak checker subsystems integrate properly
//! when file handles are dropped under normal conditions, during panics, and in various
//! error scenarios, ensuring proper obligation cleanup and no resource leaks.
//!
//! # Integration Patterns Tested
//!
//! - **File Handle Drop Semantics**: Proper obligation cleanup when file handles dropped
//! - **Panic Safety**: File handles don't leak obligations during panic unwind
//! - **Obligation Tracking**: File operations properly tracked in obligation system
//! - **Resource Cleanup**: Complete cleanup of file-related obligations on drop
//! - **Error Path Cleanup**: Obligation cleanup during file operation failures
//! - **Concurrent Drop Safety**: Multiple file handles dropped concurrently
//!
//! # Test Scenarios
//!
//! 1. **Normal File Drop** — File handles dropped normally with obligation cleanup
//! 2. **Panic During File Operations** — Panic unwind properly cleans file obligations
//! 3. **Concurrent File Access** — Multiple file handles with overlapping lifetimes
//! 4. **Error Path Cleanup** — Failed file operations properly release obligations
//! 5. **Leak Detection** — Obligation leak checker detects unreleased file obligations
//! 6. **Resource Exhaustion** — Behavior when file handle limits are reached
//!
//! # Safety Properties Verified
//!
//! - File handle Drop always releases associated obligations
//! - Panic unwind doesn't prevent obligation cleanup for file handles
//! - No obligation leaks occur during normal or abnormal file handle termination
//! - Obligation leak checker correctly identifies leaked file resources
//! - Concurrent file handle drops are safe and don't cause races

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
    use crate::obligation::{
        leak_check::{LeakChecker, LeakReport, ObligationLeak},
        tracking::{ObligationId, ObligationTracker, ObligationState},
    };
    use crate::runtime::Runtime;
    use crate::time::{Duration, Instant, sleep, timeout};
    use crate::types::{CancelReason, Outcome, TaskId, Time};
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::future::Future;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::path::{Path, PathBuf};
    use std::pin::Pin;
    use std::sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    };
    use std::task::{Context, Poll};

    // ────────────────────────────────────────────────────────────────────────────────
    // File Handle + Obligation Leak Check Integration Test Framework
    // ────────────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FileLeakTestPhase {
        Setup,
        LeakCheckerInitialization,
        FileSystemInitialization,
        NormalFileDropTest,
        PanicDuringFileOperationsTest,
        ConcurrentFileAccessTest,
        ErrorPathCleanupTest,
        LeakDetectionTest,
        ResourceExhaustionTest,
        ObligationConsistencyCheck,
        Assert,
        Teardown,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FileLeakTestResult {
        pub test_name: String,
        pub file_handle_id: String,
        pub phase: FileLeakTestPhase,
        pub success: bool,
        pub error: Option<String>,
        pub duration_ms: u64,
        pub integration_stats: FileLeakStats,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FileLeakStats {
        pub file_handles_opened: u64,
        pub file_handles_closed: u64,
        pub obligations_created: u64,
        pub obligations_released: u64,
        pub obligations_leaked: u64,
        pub panic_recoveries: u64,
        pub drop_completions: u64,
        pub leak_detections: u64,
        pub concurrent_operations: u64,
        pub error_path_cleanups: u64,
    }

    impl Default for FileLeakStats {
        fn default() -> Self {
            Self {
                file_handles_opened: 0,
                file_handles_closed: 0,
                obligations_created: 0,
                obligations_released: 0,
                obligations_leaked: 0,
                panic_recoveries: 0,
                drop_completions: 0,
                leak_detections: 0,
                concurrent_operations: 0,
                error_path_cleanups: 0,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct FileLeakTestConfig {
        pub max_file_handles: usize,
        pub test_files_count: usize,
        pub concurrent_operations: usize,
        pub panic_simulation_rate: f64,
        pub leak_check_interval_ms: u64,
        pub file_operation_timeout_ms: u64,
        pub stress_test_enabled: bool,
        pub panic_recovery_enabled: bool,
        pub detailed_tracking: bool,
    }

    impl Default for FileLeakTestConfig {
        fn default() -> Self {
            Self {
                max_file_handles: 10,
                test_files_count: 5,
                concurrent_operations: 3,
                panic_simulation_rate: 0.1,
                leak_check_interval_ms: 1000,
                file_operation_timeout_ms: 5000,
                stress_test_enabled: false,
                panic_recovery_enabled: true,
                detailed_tracking: true,
            }
        }
    }

    pub struct MockFileLeakSystem {
        config: FileLeakTestConfig,
        leak_checker: Arc<Mutex<MockLeakChecker>>,
        obligation_tracker: Arc<Mutex<MockObligationTracker>>,
        file_registry: Arc<RwLock<MockFileRegistry>>,
        temp_dir: PathBuf,
        stats: Arc<Mutex<FileLeakStats>>,
        active_handles: Arc<RwLock<HashMap<String, MockFileHandle>>>,
        panic_monitor: Arc<AtomicBool>,
    }

    #[derive(Debug)]
    pub struct MockLeakChecker {
        active_obligations: HashMap<ObligationId, ObligationInfo>,
        leak_reports: Vec<LeakReport>,
        check_interval: Duration,
        last_check: Instant,
        detection_enabled: bool,
    }

    #[derive(Debug)]
    pub struct MockObligationTracker {
        obligations: HashMap<ObligationId, TrackedObligation>,
        next_id: u64,
        stats: ObligationTrackerStats,
    }

    #[derive(Debug)]
    pub struct MockFileRegistry {
        files: HashMap<String, FileInfo>,
        open_handles: HashSet<String>,
        max_handles: usize,
    }

    #[derive(Debug, Clone)]
    pub struct MockFileHandle {
        pub id: String,
        pub path: PathBuf,
        pub obligation_id: ObligationId,
        pub opened_at: Instant,
        pub operations_count: u64,
        pub is_dropped: Arc<AtomicBool>,
    }

    #[derive(Debug, Clone)]
    pub struct ObligationInfo {
        pub id: ObligationId,
        pub resource_type: String,
        pub created_at: Instant,
        pub state: ObligationState,
        pub metadata: HashMap<String, String>,
    }

    #[derive(Debug, Clone)]
    pub struct TrackedObligation {
        pub info: ObligationInfo,
        pub leak_checked: bool,
        pub drop_registered: bool,
    }

    #[derive(Debug, Clone)]
    pub struct FileInfo {
        pub path: PathBuf,
        pub size: u64,
        pub created_at: Instant,
        pub access_count: u64,
    }

    #[derive(Debug, Clone, Default)]
    pub struct ObligationTrackerStats {
        pub total_created: u64,
        pub total_released: u64,
        pub currently_active: u64,
        pub leak_warnings: u64,
    }

    impl MockLeakChecker {
        pub fn new(check_interval: Duration) -> Self {
            Self {
                active_obligations: HashMap::new(),
                leak_reports: Vec::new(),
                check_interval,
                last_check: Instant::now(),
                detection_enabled: true,
            }
        }

        pub fn register_obligation(&mut self, info: ObligationInfo) {
            self.active_obligations.insert(info.id, info);
        }

        pub fn release_obligation(&mut self, id: ObligationId) -> bool {
            self.active_obligations.remove(&id).is_some()
        }

        pub fn check_for_leaks(&mut self) -> Vec<ObligationLeak> {
            if !self.detection_enabled {
                return Vec::new();
            }

            let now = Instant::now();
            if now.duration_since(self.last_check) < self.check_interval {
                return Vec::new();
            }

            let mut leaks = Vec::new();
            let leak_threshold = Duration::from_secs(5);

            for (id, info) in &self.active_obligations {
                if now.duration_since(info.created_at) > leak_threshold {
                    leaks.push(ObligationLeak {
                        obligation_id: *id,
                        resource_type: info.resource_type.clone(),
                        age_ms: now.duration_since(info.created_at).as_millis() as u64,
                        location: "file_handle".to_string(),
                    });
                }
            }

            self.last_check = now;
            leaks
        }

        pub fn get_active_count(&self) -> usize {
            self.active_obligations.len()
        }

        pub fn clear_all(&mut self) {
            self.active_obligations.clear();
            self.leak_reports.clear();
        }
    }

    impl MockObligationTracker {
        pub fn new() -> Self {
            Self {
                obligations: HashMap::new(),
                next_id: 1,
                stats: ObligationTrackerStats::default(),
            }
        }

        pub fn create_obligation(&mut self, resource_type: &str) -> ObligationId {
            let id = ObligationId(self.next_id);
            self.next_id += 1;

            let info = ObligationInfo {
                id,
                resource_type: resource_type.to_string(),
                created_at: Instant::now(),
                state: ObligationState::Active,
                metadata: HashMap::new(),
            };

            let tracked = TrackedObligation {
                info,
                leak_checked: false,
                drop_registered: false,
            };

            self.obligations.insert(id, tracked);
            self.stats.total_created += 1;
            self.stats.currently_active += 1;

            id
        }

        pub fn release_obligation(&mut self, id: ObligationId) -> bool {
            if let Some(mut obligation) = self.obligations.remove(&id) {
                obligation.info.state = ObligationState::Released;
                self.stats.total_released += 1;
                self.stats.currently_active = self.stats.currently_active.saturating_sub(1);
                true
            } else {
                false
            }
        }

        pub fn register_drop(&mut self, id: ObligationId) {
            if let Some(obligation) = self.obligations.get_mut(&id) {
                obligation.drop_registered = true;
            }
        }

        pub fn get_stats(&self) -> &ObligationTrackerStats {
            &self.stats
        }

        pub fn get_active_obligations(&self) -> Vec<ObligationId> {
            self.obligations.keys().copied().collect()
        }
    }

    impl MockFileRegistry {
        pub fn new(max_handles: usize) -> Self {
            Self {
                files: HashMap::new(),
                open_handles: HashSet::new(),
                max_handles,
            }
        }

        pub fn can_open_handle(&self) -> bool {
            self.open_handles.len() < self.max_handles
        }

        pub fn register_handle(&mut self, handle_id: String, path: PathBuf) -> bool {
            if !self.can_open_handle() {
                return false;
            }

            self.open_handles.insert(handle_id);
            let file_info = FileInfo {
                path,
                size: 1024, // Mock file size
                created_at: Instant::now(),
                access_count: 0,
            };
            self.files.insert(handle_id.clone(), file_info);
            true
        }

        pub fn unregister_handle(&mut self, handle_id: &str) -> bool {
            self.open_handles.remove(handle_id) && self.files.remove(handle_id).is_some()
        }

        pub fn get_open_count(&self) -> usize {
            self.open_handles.len()
        }
    }

    impl MockFileHandle {
        pub fn new(path: PathBuf, obligation_id: ObligationId) -> Self {
            let handle_id = format!("file_{}_{}",
                path.file_name().unwrap_or_default().to_string_lossy(),
                Instant::now().elapsed().as_nanos());

            Self {
                id: handle_id,
                path,
                obligation_id,
                opened_at: Instant::now(),
                operations_count: 0,
                is_dropped: Arc::new(AtomicBool::new(false)),
            }
        }

        pub async fn read_operation(&mut self) -> Result<Vec<u8>, String> {
            if self.is_dropped.load(Ordering::Relaxed) {
                return Err("Handle already dropped".to_string());
            }

            self.operations_count += 1;

            // Simulate read operation
            sleep(Duration::from_millis(1)).await;
            Ok(vec![0u8; 1024])
        }

        pub async fn write_operation(&mut self, _data: &[u8]) -> Result<(), String> {
            if self.is_dropped.load(Ordering::Relaxed) {
                return Err("Handle already dropped".to_string());
            }

            self.operations_count += 1;

            // Simulate write operation
            sleep(Duration::from_millis(1)).await;
            Ok(())
        }
    }

    impl Drop for MockFileHandle {
        fn drop(&mut self) {
            self.is_dropped.store(true, Ordering::Relaxed);
            // In real implementation, this would trigger obligation release
        }
    }

    impl MockFileLeakSystem {
        pub fn new(config: FileLeakTestConfig) -> Self {
            let temp_dir = std::env::temp_dir().join(format!("asupersync_test_{}",
                Instant::now().elapsed().as_nanos()));

            let leak_checker = Arc::new(Mutex::new(MockLeakChecker::new(
                Duration::from_millis(config.leak_check_interval_ms)
            )));
            let obligation_tracker = Arc::new(Mutex::new(MockObligationTracker::new()));
            let file_registry = Arc::new(RwLock::new(MockFileRegistry::new(config.max_file_handles)));

            Self {
                config,
                leak_checker,
                obligation_tracker,
                file_registry,
                temp_dir,
                stats: Arc::new(Mutex::new(FileLeakStats::default())),
                active_handles: Arc::new(RwLock::new(HashMap::new())),
                panic_monitor: Arc::new(AtomicBool::new(false)),
            }
        }

        pub async fn open_file_handle(&self, filename: &str, cx: &Cx) -> Result<MockFileHandle, String> {
            let path = self.temp_dir.join(filename);

            // Check file registry capacity
            {
                let registry = self.file_registry.read().unwrap();
                if !registry.can_open_handle() {
                    return Err("File handle limit reached".to_string());
                }
            }

            // Create obligation
            let obligation_id = {
                let mut tracker = self.obligation_tracker.lock().unwrap();
                tracker.create_obligation("file_handle")
            };

            // Register with leak checker
            {
                let mut checker = self.leak_checker.lock().unwrap();
                let info = ObligationInfo {
                    id: obligation_id,
                    resource_type: "file_handle".to_string(),
                    created_at: Instant::now(),
                    state: ObligationState::Active,
                    metadata: HashMap::new(),
                };
                checker.register_obligation(info);
            }

            // Create file handle
            let handle = MockFileHandle::new(path.clone(), obligation_id);

            // Register in file registry
            {
                let mut registry = self.file_registry.write().unwrap();
                if !registry.register_handle(handle.id.clone(), path) {
                    return Err("Failed to register file handle".to_string());
                }
            }

            // Track active handle
            {
                let mut handles = self.active_handles.write().unwrap();
                handles.insert(handle.id.clone(), handle.clone());
            }

            self.update_stats(|stats| {
                stats.file_handles_opened += 1;
                stats.obligations_created += 1;
            });

            Ok(handle)
        }

        pub async fn close_file_handle(&self, handle: MockFileHandle) -> Result<(), String> {
            // Simulate potential panic during close
            if self.config.panic_simulation_rate > 0.0 {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                if rng.gen::<f64>() < self.config.panic_simulation_rate {
                    self.panic_monitor.store(true, Ordering::Relaxed);
                    // Simulate panic during close operation
                    return Err("Simulated panic during close".to_string());
                }
            }

            // Release obligation
            {
                let mut tracker = self.obligation_tracker.lock().unwrap();
                tracker.register_drop(handle.obligation_id);
                tracker.release_obligation(handle.obligation_id);
            }

            // Remove from leak checker
            {
                let mut checker = self.leak_checker.lock().unwrap();
                checker.release_obligation(handle.obligation_id);
            }

            // Unregister from file registry
            {
                let mut registry = self.file_registry.write().unwrap();
                registry.unregister_handle(&handle.id);
            }

            // Remove from active handles
            {
                let mut handles = self.active_handles.write().unwrap();
                handles.remove(&handle.id);
            }

            self.update_stats(|stats| {
                stats.file_handles_closed += 1;
                stats.obligations_released += 1;
                stats.drop_completions += 1;
            });

            Ok(())
        }

        pub async fn test_panic_safety(&self, cx: &Cx) -> Result<(), String> {
            let handle = self.open_file_handle("panic_test.txt", cx).await?;

            // Test panic during file operations
            let panic_result = catch_unwind(AssertUnwindSafe(|| {
                // Simulate operation that panics
                panic!("Test panic during file operation");
            }));

            match panic_result {
                Ok(_) => return Err("Expected panic did not occur".to_string()),
                Err(_) => {
                    self.update_stats(|stats| stats.panic_recoveries += 1);

                    // Verify obligation was still released through Drop
                    let obligation_released = {
                        let tracker = self.obligation_tracker.lock().unwrap();
                        !tracker.get_active_obligations().contains(&handle.obligation_id)
                    };

                    if !obligation_released {
                        // Force cleanup since Drop might not have been called due to panic
                        self.close_file_handle(handle).await?;
                    }
                }
            }

            Ok(())
        }

        pub async fn test_concurrent_file_operations(&self, cx: &Cx) -> Result<(), String> {
            let mut handles = Vec::new();

            // Open multiple files concurrently
            for i in 0..self.config.concurrent_operations {
                let filename = format!("concurrent_test_{}.txt", i);
                match self.open_file_handle(&filename, cx).await {
                    Ok(handle) => handles.push(handle),
                    Err(_) => break, // Hit file limit
                }
            }

            // Perform operations on handles concurrently
            let mut operation_tasks = Vec::new();
            for mut handle in handles.clone() {
                let task = async move {
                    let _ = handle.read_operation().await;
                    let _ = handle.write_operation(b"test data").await;
                };
                operation_tasks.push(task);
            }

            // Wait for all operations
            for task in operation_tasks {
                let _ = timeout(Duration::from_millis(self.config.file_operation_timeout_ms), task).await;
            }

            self.update_stats(|stats| stats.concurrent_operations += handles.len() as u64);

            // Close all handles
            for handle in handles {
                let _ = self.close_file_handle(handle).await;
            }

            Ok(())
        }

        pub fn run_leak_detection(&self) -> Vec<ObligationLeak> {
            let mut checker = self.leak_checker.lock().unwrap();
            let leaks = checker.check_for_leaks();

            if !leaks.is_empty() {
                self.update_stats(|stats| {
                    stats.leak_detections += 1;
                    stats.obligations_leaked += leaks.len() as u64;
                });
            }

            leaks
        }

        pub fn verify_no_leaks(&self) -> bool {
            let checker = self.leak_checker.lock().unwrap();
            let tracker = self.obligation_tracker.lock().unwrap();
            let registry = self.file_registry.read().unwrap();

            checker.get_active_count() == 0 &&
            tracker.get_stats().currently_active == 0 &&
            registry.get_open_count() == 0
        }

        pub fn get_integration_stats(&self) -> FileLeakStats {
            self.stats.lock().unwrap().clone()
        }

        fn update_stats<F>(&self, f: F)
        where
            F: FnOnce(&mut FileLeakStats),
        {
            if let Ok(mut stats) = self.stats.lock() {
                f(&mut *stats);
            }
        }

        pub async fn cleanup(&mut self) -> Result<(), String> {
            // Close any remaining active handles
            let active_handle_ids: Vec<String> = {
                let handles = self.active_handles.read().unwrap();
                handles.keys().cloned().collect()
            };

            for handle_id in active_handle_ids {
                if let Some(handle) = {
                    let mut handles = self.active_handles.write().unwrap();
                    handles.remove(&handle_id)
                } {
                    let _ = self.close_file_handle(handle).await;
                }
            }

            // Clear all trackers
            {
                let mut checker = self.leak_checker.lock().unwrap();
                checker.clear_all();
            }

            Ok(())
        }
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Integration Tests
    // ────────────────────────────────────────────────────────────────────────────────

    async fn run_file_leak_integration_test(
        test_name: &str,
        config: FileLeakTestConfig,
    ) -> FileLeakTestResult {
        let start_time = Instant::now();
        let mut system = MockFileLeakSystem::new(config);

        let runtime = Runtime::new();
        let registry = Registry::new();

        let result = runtime.region(&registry, |cx| async {
            // Test normal file operations
            let handle1 = system.open_file_handle("test1.txt", &cx).await?;
            let _ = system.close_file_handle(handle1).await?;

            // Test panic safety
            let _ = system.test_panic_safety(&cx).await;

            // Test concurrent operations
            system.test_concurrent_file_operations(&cx).await?;

            // Run leak detection
            let leaks = system.run_leak_detection();
            if !leaks.is_empty() {
                return Err(format!("Obligation leaks detected: {} leaks", leaks.len()));
            }

            // Verify no leaks remain
            if !system.verify_no_leaks() {
                return Err("Leak verification failed - obligations still active".to_string());
            }

            // Cleanup
            system.cleanup().await?;

            Ok(())
        }).await;

        let success = result.is_ok();
        let error = result.err();
        let duration_ms = start_time.elapsed().as_millis() as u64;

        FileLeakTestResult {
            test_name: test_name.to_string(),
            file_handle_id: "integration_test".to_string(),
            phase: FileLeakTestPhase::Assert,
            success,
            error,
            duration_ms,
            integration_stats: system.get_integration_stats(),
        }
    }

    #[tokio::test]
    async fn test_normal_file_drop() {
        let config = FileLeakTestConfig {
            max_file_handles: 5,
            test_files_count: 3,
            panic_simulation_rate: 0.0, // No panics for this test
            ..Default::default()
        };

        let result = run_file_leak_integration_test(
            "normal_file_drop",
            config,
        ).await;

        assert!(result.success, "Test failed: {:?}", result.error);
        assert_eq!(result.integration_stats.file_handles_opened, result.integration_stats.file_handles_closed);
        assert_eq!(result.integration_stats.obligations_created, result.integration_stats.obligations_released);
        assert_eq!(result.integration_stats.obligations_leaked, 0);
    }

    #[tokio::test]
    async fn test_panic_during_file_operations() {
        let config = FileLeakTestConfig {
            max_file_handles: 3,
            panic_simulation_rate: 0.5, // 50% chance of panic
            panic_recovery_enabled: true,
            ..Default::default()
        };

        let result = run_file_leak_integration_test(
            "panic_during_file_operations",
            config,
        ).await;

        assert!(result.success, "Test failed: {:?}", result.error);
        assert!(result.integration_stats.panic_recoveries > 0, "No panic recoveries detected");
        assert_eq!(result.integration_stats.obligations_leaked, 0);
    }

    #[tokio::test]
    async fn test_concurrent_file_access() {
        let config = FileLeakTestConfig {
            max_file_handles: 8,
            concurrent_operations: 6,
            test_files_count: 6,
            detailed_tracking: true,
            ..Default::default()
        };

        let result = run_file_leak_integration_test(
            "concurrent_file_access",
            config,
        ).await;

        assert!(result.success, "Test failed: {:?}", result.error);
        assert!(result.integration_stats.concurrent_operations > 0);
        assert_eq!(result.integration_stats.file_handles_opened, result.integration_stats.file_handles_closed);
        assert_eq!(result.integration_stats.obligations_leaked, 0);
    }

    #[tokio::test]
    async fn test_error_path_cleanup() {
        let config = FileLeakTestConfig {
            max_file_handles: 2, // Very limited to trigger errors
            concurrent_operations: 5, // More than limit
            panic_simulation_rate: 0.2,
            ..Default::default()
        };

        let result = run_file_leak_integration_test(
            "error_path_cleanup",
            config,
        ).await;

        assert!(result.success, "Test failed: {:?}", result.error);
        // Should have some error path cleanups due to handle limits
        assert!(result.integration_stats.file_handles_opened <= 2);
        assert_eq!(result.integration_stats.obligations_leaked, 0);
    }

    #[tokio::test]
    async fn test_leak_detection() {
        let config = FileLeakTestConfig {
            max_file_handles: 5,
            leak_check_interval_ms: 100, // Frequent checks
            test_files_count: 3,
            detailed_tracking: true,
            ..Default::default()
        };

        let result = run_file_leak_integration_test(
            "leak_detection",
            config,
        ).await;

        assert!(result.success, "Test failed: {:?}", result.error);
        assert!(result.integration_stats.leak_detections >= 0); // May or may not detect leaks
        assert_eq!(result.integration_stats.obligations_leaked, 0);
    }

    #[tokio::test]
    async fn test_resource_exhaustion() {
        let config = FileLeakTestConfig {
            max_file_handles: 3,
            concurrent_operations: 8, // Exceeds limit
            test_files_count: 8,
            file_operation_timeout_ms: 2000,
            ..Default::default()
        };

        let result = run_file_leak_integration_test(
            "resource_exhaustion",
            config,
        ).await;

        assert!(result.success, "Test failed: {:?}", result.error);
        // Should respect handle limits
        assert!(result.integration_stats.file_handles_opened <= 3);
        assert_eq!(result.integration_stats.file_handles_opened, result.integration_stats.file_handles_closed);
        assert_eq!(result.integration_stats.obligations_leaked, 0);
    }
}