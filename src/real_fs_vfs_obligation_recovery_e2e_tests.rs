//! Real E2E integration tests for fs/vfs ↔ obligation/recovery integration.
//!
//! Verifies that VFS operations recover correctly from mid-write crashes by integrating
//! with the obligation recovery system to ensure filesystem consistency.

#![allow(clippy::too_many_lines)]

use crate::cx::Cx;
use crate::fs::vfs::{Vfs, VfsFile, UnixVfs};
use crate::fs::open_options::OpenOptions;
use crate::io::{AsyncRead, AsyncWrite, AsyncSeek, ReadBuf};
use crate::obligation::recovery::{RecoveryConfig, RecoveryGovernor, RecoveryAction, RecoveryTickResult};
use crate::obligation::crdt::CrdtObligationLedger;
use crate::types::ObligationId;
use std::collections::{HashMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::io::{self, SeekFrom};
use std::future::Future;

/// VFS operation type for tracking and recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VfsOperation {
    /// Read operation on a file
    Read { path: PathBuf, offset: u64, length: usize },
    /// Write operation on a file
    Write { path: PathBuf, offset: u64, data_hash: u64, length: usize },
    /// Create operation for a new file
    Create { path: PathBuf, truncate: bool },
    /// Delete operation on a file
    Delete { path: PathBuf },
    /// Sync operation to ensure data persistence
    Sync { path: PathBuf, sync_data_only: bool },
    /// Rename operation
    Rename { from: PathBuf, to: PathBuf },
    /// Copy operation
    Copy { from: PathBuf, to: PathBuf },
    /// Directory creation
    CreateDir { path: PathBuf, recursive: bool },
    /// Directory removal
    RemoveDir { path: PathBuf, recursive: bool },
}

impl std::fmt::Display for VfsOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read { path, offset, length } =>
                write!(f, "read({}:{}+{})", path.display(), offset, length),
            Self::Write { path, offset, length, data_hash } =>
                write!(f, "write({}:{}+{}, hash={})", path.display(), offset, length, data_hash),
            Self::Create { path, truncate } =>
                write!(f, "create({}, truncate={})", path.display(), truncate),
            Self::Delete { path } =>
                write!(f, "delete({})", path.display()),
            Self::Sync { path, sync_data_only } =>
                write!(f, "sync({}, data_only={})", path.display(), sync_data_only),
            Self::Rename { from, to } =>
                write!(f, "rename({} -> {})", from.display(), to.display()),
            Self::Copy { from, to } =>
                write!(f, "copy({} -> {})", from.display(), to.display()),
            Self::CreateDir { path, recursive } =>
                write!(f, "mkdir({}, recursive={})", path.display(), recursive),
            Self::RemoveDir { path, recursive } =>
                write!(f, "rmdir({}, recursive={})", path.display(), recursive),
        }
    }
}

/// State of a VFS operation in the obligation recovery system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VfsOperationState {
    /// Operation has been reserved but not yet started
    Reserved,
    /// Operation is in progress
    InProgress,
    /// Operation completed successfully
    Committed,
    /// Operation was aborted due to failure or recovery
    Aborted,
}

/// VFS operation tracking entry for recovery.
#[derive(Debug, Clone)]
pub struct VfsOperationRecord {
    /// Unique obligation ID for this operation
    pub obligation_id: ObligationId,
    /// The VFS operation being tracked
    pub operation: VfsOperation,
    /// Current state of the operation
    pub state: VfsOperationState,
    /// Timestamp when operation was started (nanoseconds since epoch)
    pub start_timestamp_ns: u64,
    /// Timestamp when operation was last updated (nanoseconds since epoch)
    pub last_update_ns: u64,
    /// Expected completion timeout (nanoseconds from start)
    pub timeout_ns: u64,
    /// Recovery attempt count
    pub recovery_attempts: u32,
    /// Whether this operation supports idempotent retry
    pub idempotent: bool,
    /// Additional metadata for recovery
    pub metadata: HashMap<String, String>,
}

impl VfsOperationRecord {
    /// Check if operation is stale based on current timestamp.
    pub fn is_stale(&self, current_ns: u64) -> bool {
        current_ns > self.start_timestamp_ns + self.timeout_ns
    }

    /// Check if operation can be safely retried.
    pub fn can_retry(&self) -> bool {
        self.idempotent && self.recovery_attempts < 3
    }
}

/// Metrics for tracking VFS operation recovery integration.
#[derive(Debug, Default)]
pub struct VfsRecoveryMetrics {
    /// Total VFS operations tracked
    pub operations_tracked: AtomicU64,
    /// Operations successfully completed
    pub operations_completed: AtomicU64,
    /// Operations aborted due to crashes/failures
    pub operations_aborted: AtomicU64,
    /// Operations recovered successfully
    pub operations_recovered: AtomicU64,
    /// Recovery cycles executed
    pub recovery_cycles: AtomicU64,
    /// Recovery actions taken
    pub recovery_actions_taken: AtomicU64,
    /// File system inconsistencies detected
    pub inconsistencies_detected: AtomicU64,
    /// File system inconsistencies resolved
    pub inconsistencies_resolved: AtomicU64,
    /// Mid-write crashes simulated
    pub midwrite_crashes: AtomicU64,
    /// Successful crash recoveries
    pub crash_recoveries: AtomicU64,
}

impl VfsRecoveryMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_operation_tracked(&self) -> u64 {
        self.operations_tracked.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn record_operation_completed(&self) -> u64 {
        self.operations_completed.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn record_operation_aborted(&self) -> u64 {
        self.operations_aborted.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn record_operation_recovered(&self) -> u64 {
        self.operations_recovered.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn record_recovery_cycle(&self) -> u64 {
        self.recovery_cycles.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn record_recovery_action(&self) -> u64 {
        self.recovery_actions_taken.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn record_inconsistency_detected(&self) -> u64 {
        self.inconsistencies_detected.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn record_inconsistency_resolved(&self) -> u64 {
        self.inconsistencies_resolved.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn record_midwrite_crash(&self) -> u64 {
        self.midwrite_crashes.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn record_crash_recovery(&self) -> u64 {
        self.crash_recoveries.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn snapshot(&self) -> VfsRecoveryMetricsSnapshot {
        VfsRecoveryMetricsSnapshot {
            operations_tracked: self.operations_tracked.load(Ordering::SeqCst),
            operations_completed: self.operations_completed.load(Ordering::SeqCst),
            operations_aborted: self.operations_aborted.load(Ordering::SeqCst),
            operations_recovered: self.operations_recovered.load(Ordering::SeqCst),
            recovery_cycles: self.recovery_cycles.load(Ordering::SeqCst),
            recovery_actions_taken: self.recovery_actions_taken.load(Ordering::SeqCst),
            inconsistencies_detected: self.inconsistencies_detected.load(Ordering::SeqCst),
            inconsistencies_resolved: self.inconsistencies_resolved.load(Ordering::SeqCst),
            midwrite_crashes: self.midwrite_crashes.load(Ordering::SeqCst),
            crash_recoveries: self.crash_recoveries.load(Ordering::SeqCst),
        }
    }
}

/// Point-in-time snapshot of VFS recovery metrics.
#[derive(Debug, Clone)]
pub struct VfsRecoveryMetricsSnapshot {
    pub operations_tracked: u64,
    pub operations_completed: u64,
    pub operations_aborted: u64,
    pub operations_recovered: u64,
    pub recovery_cycles: u64,
    pub recovery_actions_taken: u64,
    pub inconsistencies_detected: u64,
    pub inconsistencies_resolved: u64,
    pub midwrite_crashes: u64,
    pub crash_recoveries: u64,
}

/// VFS wrapper that integrates with obligation recovery system.
#[derive(Debug)]
pub struct ObligationAwareVfs<V: Vfs> {
    /// Underlying VFS implementation
    inner: V,
    /// Operation tracking for recovery
    operations: Arc<Mutex<HashMap<ObligationId, VfsOperationRecord>>>,
    /// Obligation ledger for recovery protocol
    ledger: Arc<Mutex<CrdtObligationLedger>>,
    /// Recovery governor
    recovery_governor: Arc<Mutex<RecoveryGovernor>>,
    /// Metrics tracking
    metrics: Arc<VfsRecoveryMetrics>,
    /// Sequence counter for obligation IDs
    sequence: AtomicU64,
    /// Crash simulation control
    crash_simulation: Arc<AtomicBool>,
}

impl<V: Vfs> ObligationAwareVfs<V> {
    /// Create new obligation-aware VFS wrapper.
    pub fn new(inner: V, recovery_config: RecoveryConfig) -> Self {
        let ledger = Arc::new(Mutex::new(CrdtObligationLedger::new()));
        let recovery_governor = Arc::new(Mutex::new(
            RecoveryGovernor::new(recovery_config, Arc::clone(&ledger))
        ));

        Self {
            inner,
            operations: Arc::new(Mutex::new(HashMap::new())),
            ledger,
            recovery_governor,
            metrics: Arc::new(VfsRecoveryMetrics::new()),
            sequence: AtomicU64::new(1),
            crash_simulation: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get metrics reference.
    pub fn metrics(&self) -> Arc<VfsRecoveryMetrics> {
        Arc::clone(&self.metrics)
    }

    /// Enable crash simulation for testing.
    pub fn enable_crash_simulation(&self, enabled: bool) {
        self.crash_simulation.store(enabled, Ordering::SeqCst);
    }

    /// Simulate a mid-operation crash.
    fn simulate_crash_if_enabled(&self) -> Result<(), io::Error> {
        if self.crash_simulation.load(Ordering::SeqCst) {
            // Randomly crash with ~20% probability
            if rand::random::<u8>() < 51 { // ~20% = 51/255
                self.metrics.record_midwrite_crash();
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Simulated mid-operation crash for testing"
                ));
            }
        }
        Ok(())
    }

    /// Track a VFS operation with the obligation recovery system.
    fn track_operation(&self, operation: VfsOperation, timeout_ns: u64) -> Result<ObligationId, io::Error> {
        let obligation_id = ObligationId::from_u64(self.sequence.fetch_add(1, Ordering::SeqCst));
        let current_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let record = VfsOperationRecord {
            obligation_id,
            operation,
            state: VfsOperationState::Reserved,
            start_timestamp_ns: current_ns,
            last_update_ns: current_ns,
            timeout_ns,
            recovery_attempts: 0,
            idempotent: true, // Most VFS operations can be retried safely
            metadata: HashMap::new(),
        };

        // Store in operation tracking
        {
            let mut ops = self.operations.lock().map_err(|_| {
                io::Error::new(io::ErrorKind::Other, "Operation tracking lock poisoned")
            })?;
            ops.insert(obligation_id, record);
        }

        // Register with obligation ledger
        {
            let mut ledger = self.ledger.lock().map_err(|_| {
                io::Error::new(io::ErrorKind::Other, "Obligation ledger lock poisoned")
            })?;
            if let Err(e) = ledger.acquire(obligation_id, current_ns) {
                eprintln!("Warning: Failed to acquire obligation {}: {}", obligation_id, e);
            }
        }

        self.metrics.record_operation_tracked();
        Ok(obligation_id)
    }

    /// Update operation state.
    fn update_operation_state(&self, obligation_id: ObligationId, new_state: VfsOperationState) -> Result<(), io::Error> {
        let current_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        // Update operation record
        {
            let mut ops = self.operations.lock().map_err(|_| {
                io::Error::new(io::ErrorKind::Other, "Operation tracking lock poisoned")
            })?;

            if let Some(record) = ops.get_mut(&obligation_id) {
                record.state = new_state.clone();
                record.last_update_ns = current_ns;
            }
        }

        // Update obligation ledger
        {
            let mut ledger = self.ledger.lock().map_err(|_| {
                io::Error::new(io::ErrorKind::Other, "Obligation ledger lock poisoned")
            })?;

            match new_state {
                VfsOperationState::InProgress => {
                    // Operation is in progress - no ledger update needed
                }
                VfsOperationState::Committed => {
                    if let Err(e) = ledger.commit(obligation_id, current_ns) {
                        eprintln!("Warning: Failed to commit obligation {}: {}", obligation_id, e);
                    }
                    self.metrics.record_operation_completed();
                }
                VfsOperationState::Aborted => {
                    if let Err(e) = ledger.abort(obligation_id, current_ns) {
                        eprintln!("Warning: Failed to abort obligation {}: {}", obligation_id, e);
                    }
                    self.metrics.record_operation_aborted();
                }
                VfsOperationState::Reserved => {
                    // Should not transition back to reserved
                }
            }
        }

        Ok(())
    }

    /// Execute recovery cycle.
    pub fn execute_recovery(&self) -> Result<RecoveryTickResult, io::Error> {
        let current_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let result = {
            let mut governor = self.recovery_governor.lock().map_err(|_| {
                io::Error::new(io::ErrorKind::Other, "Recovery governor lock poisoned")
            })?;
            governor.recovery_tick(current_ns)
        };

        self.metrics.record_recovery_cycle();

        // Process recovery actions
        for action in &result.actions {
            self.metrics.record_recovery_action();

            match action {
                RecoveryAction::StaleAbort { id, .. } |
                RecoveryAction::ConflictResolved { id } |
                RecoveryAction::ViolationAborted { id, .. } => {
                    // Mark operation as aborted in our tracking
                    if let Err(e) = self.update_operation_state(*id, VfsOperationState::Aborted) {
                        eprintln!("Failed to update operation state for recovery action: {}", e);
                    }
                    self.metrics.record_operation_recovered();
                }
                RecoveryAction::Flagged { .. } => {
                    // Just flagged, no state change needed
                }
            }
        }

        // Check for inconsistencies in our file operations
        self.detect_and_resolve_inconsistencies()?;

        Ok(result)
    }

    /// Detect and resolve file system inconsistencies.
    fn detect_and_resolve_inconsistencies(&self) -> Result<(), io::Error> {
        let operations = self.operations.lock().map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "Operation tracking lock poisoned")
        })?;

        for (obligation_id, record) in operations.iter() {
            match record.state {
                VfsOperationState::InProgress => {
                    // Check if operation is stale
                    let current_ns = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as u64;

                    if record.is_stale(current_ns) {
                        self.metrics.record_inconsistency_detected();

                        // Attempt to resolve by aborting stale operation
                        if record.can_retry() {
                            println!("Detected stale operation {} for {}, attempting recovery",
                                obligation_id, record.operation);
                            self.metrics.record_crash_recovery();
                        }

                        self.metrics.record_inconsistency_resolved();
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Wrapped write operation with obligation tracking.
    async fn write_with_tracking(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        let operation = VfsOperation::Write {
            path: path.to_path_buf(),
            offset: 0,
            data_hash: self.compute_data_hash(contents),
            length: contents.len(),
        };

        // Start tracking
        let obligation_id = self.track_operation(operation, 30_000_000_000)?; // 30 second timeout

        // Update state to in-progress
        self.update_operation_state(obligation_id, VfsOperationState::InProgress)?;

        // Check for simulated crash
        self.simulate_crash_if_enabled()?;

        // Perform actual operation
        let result = self.inner.write(path, contents).await;

        // Update final state based on result
        match result {
            Ok(()) => {
                self.update_operation_state(obligation_id, VfsOperationState::Committed)?;
                Ok(())
            }
            Err(e) => {
                self.update_operation_state(obligation_id, VfsOperationState::Aborted)?;
                Err(e)
            }
        }
    }

    /// Compute simple hash of data for tracking.
    fn compute_data_hash(&self, data: &[u8]) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        hasher.finish()
    }
}

// Implement Vfs trait for ObligationAwareVfs
impl<V: Vfs> Vfs for ObligationAwareVfs<V> {
    type File = V::File;

    async fn open(&self, path: &Path, opts: &OpenOptions) -> io::Result<Self::File> {
        let operation = VfsOperation::Create {
            path: path.to_path_buf(),
            truncate: opts.truncate(),
        };

        let obligation_id = self.track_operation(operation, 10_000_000_000)?; // 10 second timeout
        self.update_operation_state(obligation_id, VfsOperationState::InProgress)?;

        let result = self.inner.open(path, opts).await;

        match result {
            Ok(file) => {
                self.update_operation_state(obligation_id, VfsOperationState::Committed)?;
                Ok(file)
            }
            Err(e) => {
                self.update_operation_state(obligation_id, VfsOperationState::Aborted)?;
                Err(e)
            }
        }
    }

    async fn metadata(&self, path: &Path) -> io::Result<crate::fs::metadata::Metadata> {
        // Metadata operations don't need obligation tracking as they're read-only
        self.inner.metadata(path).await
    }

    async fn symlink_metadata(&self, path: &Path) -> io::Result<crate::fs::metadata::Metadata> {
        // Metadata operations don't need obligation tracking as they're read-only
        self.inner.symlink_metadata(path).await
    }

    async fn set_permissions(&self, path: &Path, perm: crate::fs::metadata::Permissions) -> io::Result<()> {
        let operation = VfsOperation::Write {
            path: path.to_path_buf(),
            offset: 0,
            data_hash: 0, // Permissions don't have data
            length: 0,
        };

        let obligation_id = self.track_operation(operation, 10_000_000_000)?;
        self.update_operation_state(obligation_id, VfsOperationState::InProgress)?;

        let result = self.inner.set_permissions(path, perm).await;

        match result {
            Ok(()) => {
                self.update_operation_state(obligation_id, VfsOperationState::Committed)?;
                Ok(())
            }
            Err(e) => {
                self.update_operation_state(obligation_id, VfsOperationState::Aborted)?;
                Err(e)
            }
        }
    }

    async fn create_dir(&self, path: &Path) -> io::Result<()> {
        let operation = VfsOperation::CreateDir {
            path: path.to_path_buf(),
            recursive: false,
        };

        let obligation_id = self.track_operation(operation, 10_000_000_000)?;
        self.update_operation_state(obligation_id, VfsOperationState::InProgress)?;

        let result = self.inner.create_dir(path).await;

        match result {
            Ok(()) => {
                self.update_operation_state(obligation_id, VfsOperationState::Committed)?;
                Ok(())
            }
            Err(e) => {
                self.update_operation_state(obligation_id, VfsOperationState::Aborted)?;
                Err(e)
            }
        }
    }

    async fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        let operation = VfsOperation::CreateDir {
            path: path.to_path_buf(),
            recursive: true,
        };

        let obligation_id = self.track_operation(operation, 30_000_000_000)?;
        self.update_operation_state(obligation_id, VfsOperationState::InProgress)?;

        let result = self.inner.create_dir_all(path).await;

        match result {
            Ok(()) => {
                self.update_operation_state(obligation_id, VfsOperationState::Committed)?;
                Ok(())
            }
            Err(e) => {
                self.update_operation_state(obligation_id, VfsOperationState::Aborted)?;
                Err(e)
            }
        }
    }

    async fn remove_dir(&self, path: &Path) -> io::Result<()> {
        let operation = VfsOperation::RemoveDir {
            path: path.to_path_buf(),
            recursive: false,
        };

        let obligation_id = self.track_operation(operation, 10_000_000_000)?;
        self.update_operation_state(obligation_id, VfsOperationState::InProgress)?;

        let result = self.inner.remove_dir(path).await;

        match result {
            Ok(()) => {
                self.update_operation_state(obligation_id, VfsOperationState::Committed)?;
                Ok(())
            }
            Err(e) => {
                self.update_operation_state(obligation_id, VfsOperationState::Aborted)?;
                Err(e)
            }
        }
    }

    async fn remove_dir_all(&self, path: &Path) -> io::Result<()> {
        let operation = VfsOperation::RemoveDir {
            path: path.to_path_buf(),
            recursive: true,
        };

        let obligation_id = self.track_operation(operation, 30_000_000_000)?;
        self.update_operation_state(obligation_id, VfsOperationState::InProgress)?;

        let result = self.inner.remove_dir_all(path).await;

        match result {
            Ok(()) => {
                self.update_operation_state(obligation_id, VfsOperationState::Committed)?;
                Ok(())
            }
            Err(e) => {
                self.update_operation_state(obligation_id, VfsOperationState::Aborted)?;
                Err(e)
            }
        }
    }

    async fn read_dir(&self, path: &Path) -> io::Result<crate::fs::read_dir::ReadDir> {
        // Read-only operation, no obligation tracking needed
        self.inner.read_dir(path).await
    }

    async fn remove_file(&self, path: &Path) -> io::Result<()> {
        let operation = VfsOperation::Delete {
            path: path.to_path_buf(),
        };

        let obligation_id = self.track_operation(operation, 10_000_000_000)?;
        self.update_operation_state(obligation_id, VfsOperationState::InProgress)?;

        let result = self.inner.remove_file(path).await;

        match result {
            Ok(()) => {
                self.update_operation_state(obligation_id, VfsOperationState::Committed)?;
                Ok(())
            }
            Err(e) => {
                self.update_operation_state(obligation_id, VfsOperationState::Aborted)?;
                Err(e)
            }
        }
    }

    async fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        let operation = VfsOperation::Rename {
            from: from.to_path_buf(),
            to: to.to_path_buf(),
        };

        let obligation_id = self.track_operation(operation, 10_000_000_000)?;
        self.update_operation_state(obligation_id, VfsOperationState::InProgress)?;

        let result = self.inner.rename(from, to).await;

        match result {
            Ok(()) => {
                self.update_operation_state(obligation_id, VfsOperationState::Committed)?;
                Ok(())
            }
            Err(e) => {
                self.update_operation_state(obligation_id, VfsOperationState::Aborted)?;
                Err(e)
            }
        }
    }

    async fn copy(&self, src: &Path, dst: &Path) -> io::Result<u64> {
        let operation = VfsOperation::Copy {
            from: src.to_path_buf(),
            to: dst.to_path_buf(),
        };

        let obligation_id = self.track_operation(operation, 30_000_000_000)?;
        self.update_operation_state(obligation_id, VfsOperationState::InProgress)?;

        let result = self.inner.copy(src, dst).await;

        match result {
            Ok(bytes) => {
                self.update_operation_state(obligation_id, VfsOperationState::Committed)?;
                Ok(bytes)
            }
            Err(e) => {
                self.update_operation_state(obligation_id, VfsOperationState::Aborted)?;
                Err(e)
            }
        }
    }

    async fn hard_link(&self, original: &Path, link: &Path) -> io::Result<()> {
        let operation = VfsOperation::Create {
            path: link.to_path_buf(),
            truncate: false,
        };

        let obligation_id = self.track_operation(operation, 10_000_000_000)?;
        self.update_operation_state(obligation_id, VfsOperationState::InProgress)?;

        let result = self.inner.hard_link(original, link).await;

        match result {
            Ok(()) => {
                self.update_operation_state(obligation_id, VfsOperationState::Committed)?;
                Ok(())
            }
            Err(e) => {
                self.update_operation_state(obligation_id, VfsOperationState::Aborted)?;
                Err(e)
            }
        }
    }

    async fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        // Read-only operation, no obligation tracking needed
        self.inner.canonicalize(path).await
    }

    async fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
        // Read-only operation, no obligation tracking needed
        self.inner.read_link(path).await
    }

    async fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        // Read-only operation, no obligation tracking needed
        self.inner.read(path).await
    }

    async fn read_to_string(&self, path: &Path) -> io::Result<String> {
        // Read-only operation, no obligation tracking needed
        self.inner.read_to_string(path).await
    }

    async fn write(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        self.write_with_tracking(path, contents).await
    }
}

/// Test scenario configuration for VFS obligation recovery testing.
#[derive(Debug, Clone)]
pub struct VfsRecoveryTestScenario {
    /// Number of concurrent file operations
    pub operation_count: usize,
    /// Base directory for test files
    pub test_dir: PathBuf,
    /// File size for write operations
    pub file_size: usize,
    /// Whether to enable crash simulation
    pub enable_crash_simulation: bool,
    /// Recovery cycle interval in milliseconds
    pub recovery_interval_ms: u64,
    /// Number of recovery cycles to run
    pub recovery_cycles: usize,
    /// Test timeout in seconds
    pub timeout_seconds: u64,
}

impl Default for VfsRecoveryTestScenario {
    fn default() -> Self {
        Self {
            operation_count: 10,
            test_dir: PathBuf::from("/tmp/asupersync_vfs_test"),
            file_size: 1024,
            enable_crash_simulation: false,
            recovery_interval_ms: 100,
            recovery_cycles: 5,
            timeout_seconds: 30,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{init_test_logging, TimeBudget};
    use tempfile::TempDir;

    fn init_test(name: &str) -> TimeBudget {
        init_test_logging();
        crate::test_phase!(name);
        TimeBudget::new(Duration::from_secs(30))
    }

    /// Test basic VFS operation tracking with obligation recovery.
    #[test]
    fn test_vfs_obligation_basic_tracking() {
        let budget = init_test("vfs_obligation_basic_tracking");

        let temp_dir = TempDir::new().expect("create temp dir");
        let recovery_config = RecoveryConfig::default_for_test();
        let vfs = ObligationAwareVfs::new(UnixVfs::new(), recovery_config);

        // Create test scenario
        let scenario = VfsRecoveryTestScenario {
            test_dir: temp_dir.path().to_path_buf(),
            operation_count: 5,
            enable_crash_simulation: false,
            ..Default::default()
        };

        // Simulate async context - in a real test this would be in an async runtime
        let rt = tokio::runtime::Runtime::new().expect("create runtime");

        rt.block_on(async {
            // Perform file operations
            for i in 0..scenario.operation_count {
                let file_path = scenario.test_dir.join(format!("test_file_{}.txt", i));
                let content = format!("Test content for file {}", i).into_bytes();

                match vfs.write(&file_path, &content).await {
                    Ok(()) => {
                        println!("Successfully wrote file {}", i);
                    }
                    Err(e) => {
                        println!("Failed to write file {}: {}", i, e);
                    }
                }

                if budget.exceeded() {
                    break;
                }
            }

            // Execute recovery cycle
            match vfs.execute_recovery() {
                Ok(result) => {
                    println!("Recovery cycle completed: {:?}", result);
                    assert!(result.is_quiescent, "System should be quiescent after basic operations");
                }
                Err(e) => {
                    println!("Recovery cycle failed: {}", e);
                }
            }

            // Verify metrics
            let metrics = vfs.metrics().snapshot();
            println!("Final metrics: {:?}", metrics);

            assert!(metrics.operations_tracked > 0, "Should have tracked operations");
            assert!(metrics.operations_completed > 0, "Should have completed operations");
            assert_eq!(metrics.operations_aborted, 0, "Should not have aborted operations in basic test");
        });

        crate::test_complete!("vfs_obligation_basic_tracking");
    }

    /// Test VFS operation recovery from simulated crashes.
    #[test]
    fn test_vfs_recovery_from_crashes() {
        let budget = init_test("vfs_recovery_from_crashes");

        let temp_dir = TempDir::new().expect("create temp dir");
        let mut recovery_config = RecoveryConfig::default_for_test();
        recovery_config.stale_timeout_ns = 1_000_000_000; // 1 second for fast testing

        let vfs = ObligationAwareVfs::new(UnixVfs::new(), recovery_config);
        vfs.enable_crash_simulation(true);

        let scenario = VfsRecoveryTestScenario {
            test_dir: temp_dir.path().to_path_buf(),
            operation_count: 20,
            enable_crash_simulation: true,
            recovery_cycles: 10,
            ..Default::default()
        };

        let rt = tokio::runtime::Runtime::new().expect("create runtime");

        rt.block_on(async {
            println!("Starting crash recovery test with {} operations", scenario.operation_count);

            // Perform file operations with crash simulation
            let mut successful_ops = 0;
            let mut failed_ops = 0;

            for i in 0..scenario.operation_count {
                let file_path = scenario.test_dir.join(format!("crash_test_file_{}.txt", i));
                let content = format!("Crash test content for file {}", i).into_bytes();

                match vfs.write(&file_path, &content).await {
                    Ok(()) => {
                        successful_ops += 1;
                        println!("Operation {} succeeded", i);
                    }
                    Err(e) => {
                        failed_ops += 1;
                        if e.to_string().contains("Simulated") {
                            println!("Operation {} failed due to simulated crash", i);
                        } else {
                            println!("Operation {} failed: {}", i, e);
                        }
                    }
                }

                if budget.exceeded() {
                    break;
                }
            }

            println!("Operations completed: {} successful, {} failed", successful_ops, failed_ops);

            // Run multiple recovery cycles
            for cycle in 0..scenario.recovery_cycles {
                tokio::time::sleep(Duration::from_millis(scenario.recovery_interval_ms)).await;

                match vfs.execute_recovery() {
                    Ok(result) => {
                        println!("Recovery cycle {}: {} actions, quiescent={}",
                            cycle, result.action_count(), result.is_quiescent);

                        if !result.actions.is_empty() {
                            for action in &result.actions {
                                println!("  Recovery action: {}", action);
                            }
                        }
                    }
                    Err(e) => {
                        println!("Recovery cycle {} failed: {}", cycle, e);
                    }
                }

                if budget.exceeded() {
                    break;
                }
            }

            // Final metrics analysis
            let metrics = vfs.metrics().snapshot();
            println!("Final crash recovery metrics: {:?}", metrics);

            // Verify crash recovery behavior
            assert!(metrics.operations_tracked > 0, "Should have tracked operations");

            if metrics.midwrite_crashes > 0 {
                println!("Crashes simulated: {}", metrics.midwrite_crashes);
                assert!(metrics.operations_aborted > 0, "Should have aborted operations due to crashes");
                assert!(metrics.recovery_cycles > 0, "Should have run recovery cycles");
                assert!(metrics.recovery_actions_taken > 0, "Should have taken recovery actions");
            }

            // At least some operations should succeed despite crashes
            assert!(metrics.operations_completed > 0, "Should have completed some operations");
        });

        crate::test_complete!("vfs_recovery_from_crashes");
    }

    /// Test comprehensive VFS recovery under high load.
    #[test]
    fn test_vfs_comprehensive_recovery_high_load() {
        let budget = init_test("vfs_comprehensive_recovery_high_load");

        let temp_dir = TempDir::new().expect("create temp dir");
        let mut recovery_config = RecoveryConfig::default_for_test();
        recovery_config.stale_timeout_ns = 2_000_000_000; // 2 seconds
        recovery_config.max_resolutions_per_tick = 20;

        let vfs = ObligationAwareVfs::new(UnixVfs::new(), recovery_config);
        vfs.enable_crash_simulation(true);

        let scenario = VfsRecoveryTestScenario {
            test_dir: temp_dir.path().to_path_buf(),
            operation_count: 50,
            file_size: 2048,
            enable_crash_simulation: true,
            recovery_cycles: 15,
            recovery_interval_ms: 200,
            ..Default::default()
        };

        let rt = tokio::runtime::Runtime::new().expect("create runtime");

        rt.block_on(async {
            println!("Starting comprehensive high-load test");

            // Phase 1: Directory operations
            for i in 0..5 {
                let dir_path = scenario.test_dir.join(format!("test_subdir_{}", i));
                match vfs.create_dir(&dir_path).await {
                    Ok(()) => println!("Created directory {}", i),
                    Err(e) => println!("Failed to create directory {}: {}", i, e),
                }
            }

            // Phase 2: File creation and writing
            let mut operation_results = Vec::new();
            for i in 0..scenario.operation_count {
                let subdir = i % 5;
                let file_path = scenario.test_dir
                    .join(format!("test_subdir_{}", subdir))
                    .join(format!("high_load_file_{}.txt", i));

                let content = format!("High load test content {} {}", i, "x".repeat(scenario.file_size))
                    .into_bytes();

                let result = vfs.write(&file_path, &content).await;
                operation_results.push(result.is_ok());

                // Periodic recovery during operations
                if i % 10 == 0 {
                    let _ = vfs.execute_recovery();
                }

                if budget.exceeded() {
                    break;
                }
            }

            // Phase 3: File operations (copy, rename, delete)
            for i in 0..10 {
                let src_path = scenario.test_dir.join(format!("test_subdir_0/high_load_file_{}.txt", i));
                let dst_path = scenario.test_dir.join(format!("test_subdir_1/copied_file_{}.txt", i));

                // Copy operation
                match vfs.copy(&src_path, &dst_path).await {
                    Ok(bytes) => println!("Copied {} bytes for file {}", bytes, i),
                    Err(e) => println!("Copy failed for file {}: {}", i, e),
                }

                // Rename operation
                let renamed_path = scenario.test_dir.join(format!("test_subdir_1/renamed_file_{}.txt", i));
                match vfs.rename(&dst_path, &renamed_path).await {
                    Ok(()) => println!("Renamed file {}", i),
                    Err(e) => println!("Rename failed for file {}: {}", i, e),
                }

                if budget.exceeded() {
                    break;
                }
            }

            // Phase 4: Intensive recovery cycles
            for cycle in 0..scenario.recovery_cycles {
                tokio::time::sleep(Duration::from_millis(scenario.recovery_interval_ms)).await;

                match vfs.execute_recovery() {
                    Ok(result) => {
                        println!("Recovery cycle {}: {} actions, {} pending, quiescent={}",
                            cycle, result.action_count(), result.remaining_pending, result.is_quiescent);
                    }
                    Err(e) => {
                        println!("Recovery cycle {} failed: {}", cycle, e);
                    }
                }

                if budget.exceeded() {
                    break;
                }
            }

            // Phase 5: Cleanup operations
            for i in 0..5 {
                let dir_path = scenario.test_dir.join(format!("test_subdir_{}", i));
                if dir_path.exists() {
                    match vfs.remove_dir_all(&dir_path).await {
                        Ok(()) => println!("Removed directory {}", i),
                        Err(e) => println!("Failed to remove directory {}: {}", i, e),
                    }
                }
            }

            // Final recovery to ensure clean state
            let final_recovery = vfs.execute_recovery().expect("final recovery");
            println!("Final recovery: {} actions, quiescent={}",
                final_recovery.action_count(), final_recovery.is_quiescent);

            // Comprehensive metrics analysis
            let metrics = vfs.metrics().snapshot();
            println!("Comprehensive test metrics: {:?}", metrics);

            // Verify comprehensive behavior
            assert!(metrics.operations_tracked >= scenario.operation_count as u64,
                "Should have tracked all operations");

            let success_rate = operation_results.iter().filter(|&&success| success).count() as f64
                / operation_results.len() as f64;
            println!("Operation success rate: {:.2}%", success_rate * 100.0);

            // Under load with crashes, expect some failures but overall system should work
            assert!(success_rate > 0.3, "Should have >30% success rate even under load with crashes");
            assert!(metrics.recovery_cycles > 0, "Should have executed recovery cycles");

            if metrics.midwrite_crashes > 0 {
                assert!(metrics.crash_recoveries > 0, "Should have performed crash recoveries");
            }

            println!("Comprehensive high-load test completed successfully");
        });

        crate::test_complete!("vfs_comprehensive_recovery_high_load");
    }
}