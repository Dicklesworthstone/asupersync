//! ATP Crash Injection and Fault Matrix
//!
//! Deterministic fault injection for testing crash-resume behavior
//! at every critical point in the ATP receiver pipeline.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use asupersync::atp::verifier::VerificationStage;

/// Fault injection point in ATP operations
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum FaultPoint {
    /// Journal operations
    JournalAppend,
    JournalFlush,
    JournalCompaction,

    /// Bitmap operations
    BitmapUpdate,
    BitmapFlush,

    /// Chunk operations
    ChunkWrite,
    ChunkVerify,

    /// Filesystem operations
    FileCreate,
    FileWrite,
    FileRename,
    FileFsync,
    DirFsync,

    /// Verification operations
    VerifyChunkHash,
    VerifyObjectContent,
    VerifyGraphMerkle,
    VerifyManifest,
    VerifyCommit,
    VerifyProofBundle,
    VerifyFinalizer,

    /// Cleanup operations
    TempCleanup,
    QuarantineMove,
    FinalExpose,
}

/// Type of fault to inject
#[derive(Debug, Clone)]
pub enum FaultType {
    /// Process crash (simulated via panic)
    Crash,
    /// IO error with specific error code
    IoError(std::io::ErrorKind),
    /// Corruption of data
    DataCorruption(CorruptionType),
    /// Timeout/hang
    Timeout,
}

/// Type of data corruption
#[derive(Debug, Clone)]
pub enum CorruptionType {
    /// Flip random bits
    BitFlip(usize),
    /// Truncate data
    Truncate(usize),
    /// Zero out data
    Zero,
    /// Inject random bytes
    RandomBytes,
}

/// Fault injection configuration
#[derive(Debug, Clone)]
pub struct FaultConfig {
    pub point: FaultPoint,
    pub fault_type: FaultType,
    pub probability: f64,             // 0.0 to 1.0
    pub trigger_count: Option<usize>, // Trigger after N occurrences
}

/// Deterministic fault injector for ATP operations
pub struct FaultInjector {
    faults: Arc<Mutex<HashMap<FaultPoint, FaultConfig>>>,
    counters: Arc<Mutex<HashMap<FaultPoint, usize>>>,
    enabled: Arc<Mutex<bool>>,
}

impl FaultInjector {
    /// Create new fault injector
    pub fn new() -> Self {
        Self {
            faults: Arc::new(Mutex::new(HashMap::new())),
            counters: Arc::new(Mutex::new(HashMap::new())),
            enabled: Arc::new(Mutex::new(true)),
        }
    }

    /// Configure fault injection at specific point
    pub fn configure_fault(&self, config: FaultConfig) {
        let mut faults = self.faults.lock().unwrap();
        faults.insert(config.point.clone(), config);
    }

    /// Inject crash at specific fault point
    pub fn inject_crash_at(&self, point_name: &str) {
        if let Ok(point) = self.parse_fault_point(point_name) {
            self.configure_fault(FaultConfig {
                point,
                fault_type: FaultType::Crash,
                probability: 1.0,
                trigger_count: Some(1),
            });
        }
    }

    /// Check if fault should be injected at given point
    pub fn should_inject(&self, point: &FaultPoint) -> Option<FaultType> {
        if !*self.enabled.lock().unwrap() {
            return None;
        }

        let faults = self.faults.lock().unwrap();
        let mut counters = self.counters.lock().unwrap();

        if let Some(config) = faults.get(point) {
            // Increment counter for this fault point
            let count = counters.entry(point.clone()).or_insert(0);
            *count += 1;

            // Check if we should trigger based on count
            if let Some(trigger_count) = config.trigger_count {
                if *count >= trigger_count {
                    return Some(config.fault_type.clone());
                }
            }

            // Check probability-based triggering
            if config.probability >= 1.0 {
                return Some(config.fault_type.clone());
            }
        }

        None
    }

    /// Execute operation with potential fault injection
    pub fn with_injection<T, F>(
        &self,
        point: FaultPoint,
        operation: F,
    ) -> Result<T, FaultInjectionError>
    where
        F: FnOnce() -> Result<T, Box<dyn std::error::Error>>,
    {
        // Check for fault injection
        if let Some(fault_type) = self.should_inject(&point) {
            return Err(FaultInjectionError::new(point, fault_type));
        }

        // Execute normal operation
        operation().map_err(|e| FaultInjectionError::OperationFailed(e))
    }

    /// Inject verifier stage crash
    pub fn inject_verifier_stage_crash(&self, stage: VerificationStage) {
        let point = match stage {
            VerificationStage::ChunkHash => FaultPoint::VerifyChunkHash,
            VerificationStage::ObjectContent => FaultPoint::VerifyObjectContent,
            VerificationStage::GraphMerkle => FaultPoint::VerifyGraphMerkle,
            VerificationStage::Manifest => FaultPoint::VerifyManifest,
            VerificationStage::Commit => FaultPoint::VerifyCommit,
            VerificationStage::ProofBundle => FaultPoint::VerifyProofBundle,
            VerificationStage::Finalizer => FaultPoint::VerifyFinalizer,
            _ => return, // Unknown stage
        };

        self.configure_fault(FaultConfig {
            point,
            fault_type: FaultType::Crash,
            probability: 1.0,
            trigger_count: Some(1),
        });
    }

    /// Enable/disable fault injection
    pub fn set_enabled(&self, enabled: bool) {
        *self.enabled.lock().unwrap() = enabled;
    }

    /// Clear all fault configurations
    pub fn clear_faults(&self) {
        self.faults.lock().unwrap().clear();
        self.counters.lock().unwrap().clear();
    }

    /// Parse fault point from string name
    fn parse_fault_point(&self, name: &str) -> Result<FaultPoint, String> {
        match name {
            "pre_journal_append" => Ok(FaultPoint::JournalAppend),
            "post_journal_append" => Ok(FaultPoint::JournalFlush),
            "post_bitmap_update" => Ok(FaultPoint::BitmapUpdate),
            "post_chunk_write" => Ok(FaultPoint::ChunkWrite),
            "post_fsync" => Ok(FaultPoint::FileFsync),
            "post_repair_decode" => Ok(FaultPoint::ChunkVerify),
            "post_final_rename" => Ok(FaultPoint::FileRename),
            "post_proof_emission" => Ok(FaultPoint::VerifyProofBundle),
            "during_compaction" => Ok(FaultPoint::JournalCompaction),
            _ => Err(format!("Unknown fault point: {}", name)),
        }
    }
}

impl Default for FaultInjector {
    fn default() -> Self {
        Self::new()
    }
}

/// Error type for fault injection
#[derive(Debug)]
pub enum FaultInjectionError {
    /// Fault was injected
    FaultInjected {
        point: FaultPoint,
        fault_type: FaultType,
    },
    /// Operation failed for other reasons
    OperationFailed(Box<dyn std::error::Error>),
}

impl FaultInjectionError {
    fn new(point: FaultPoint, fault_type: FaultType) -> Self {
        match fault_type {
            FaultType::Crash => {
                // Simulate crash via panic
                panic!("Injected crash at {:?}", point);
            }
            _ => Self::FaultInjected { point, fault_type },
        }
    }
}

impl std::fmt::Display for FaultInjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FaultInjected { point, fault_type } => {
                write!(f, "Fault injected at {:?}: {:?}", point, fault_type)
            }
            Self::OperationFailed(err) => write!(f, "Operation failed: {}", err),
        }
    }
}

impl std::error::Error for FaultInjectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OperationFailed(err) => Some(err.as_ref()),
            _ => None,
        }
    }
}

/// Macro for easy fault injection integration
#[macro_export]
macro_rules! with_fault_injection {
    ($injector:expr, $point:expr, $operation:block) => {
        $injector.with_injection($point, || $operation)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fault_injector_creation() {
        let injector = FaultInjector::new();
        assert!(injector.should_inject(&FaultPoint::JournalAppend).is_none());
    }

    #[test]
    fn test_crash_injection_configuration() {
        let injector = FaultInjector::new();

        injector.configure_fault(FaultConfig {
            point: FaultPoint::JournalAppend,
            fault_type: FaultType::Crash,
            probability: 1.0,
            trigger_count: Some(1),
        });

        // First check should trigger crash (via panic in real usage)
        // We can't test actual panic here, but we can verify configuration
        assert!(matches!(
            injector.should_inject(&FaultPoint::JournalAppend),
            Some(FaultType::Crash)
        ));
    }

    #[test]
    fn test_fault_point_parsing() {
        let injector = FaultInjector::new();

        assert!(matches!(
            injector.parse_fault_point("pre_journal_append"),
            Ok(FaultPoint::JournalAppend)
        ));

        assert!(injector.parse_fault_point("unknown_point").is_err());
    }
}
