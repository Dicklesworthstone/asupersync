//! ATP Obligation Tracking and Leak Detection
//!
//! Ensures no obligation leaks occur during crash-resume testing
//! and validates region quiescence after failures.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

/// Obligation types tracked in ATP testing
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum ObligationType {
    /// Transfer obligation
    Transfer(String),
    /// Verification obligation
    Verification(String),
    /// Journal obligation
    Journal(String),
    /// Cleanup obligation
    Cleanup(String),
    /// Worker obligation
    Worker(String),
    /// Region obligation
    Region(String),
}

/// State of an obligation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObligationState {
    /// Obligation is active
    Active,
    /// Obligation is being fulfilled
    Fulfilling,
    /// Obligation has been fulfilled
    Fulfilled,
    /// Obligation was cancelled
    Cancelled,
    /// Obligation leaked (not properly cleaned up)
    Leaked,
}

/// Information about an obligation
#[derive(Debug, Clone)]
pub struct ObligationInfo {
    pub obligation_id: String,
    pub obligation_type: ObligationType,
    pub state: ObligationState,
    pub created_at: Instant,
    pub last_updated: Instant,
    pub creator: String,
    pub context: HashMap<String, String>,
}

/// ATP obligation tracker
pub struct AtpObligationTracker {
    obligations: Arc<Mutex<HashMap<String, ObligationInfo>>>,
    watchers: Arc<Mutex<Vec<Weak<dyn ObligationWatcher>>>>,
    leak_detection_enabled: bool,
}

/// Obligation watcher trait
pub trait ObligationWatcher: Send + Sync {
    /// Called when obligation state changes
    fn on_obligation_changed(&self, info: &ObligationInfo);
    /// Called when leak is detected
    fn on_leak_detected(&self, info: &ObligationInfo);
}

impl AtpObligationTracker {
    /// Create new obligation tracker
    pub fn new() -> Self {
        Self {
            obligations: Arc::new(Mutex::new(HashMap::new())),
            watchers: Arc::new(Mutex::new(Vec::new())),
            leak_detection_enabled: true,
        }
    }

    /// Create new obligation
    pub fn create_obligation(
        &self,
        obligation_type: ObligationType,
        creator: String,
        context: HashMap<String, String>,
    ) -> String {
        let obligation_id = generate_obligation_id();
        let now = Instant::now();

        let info = ObligationInfo {
            obligation_id: obligation_id.clone(),
            obligation_type,
            state: ObligationState::Active,
            created_at: now,
            last_updated: now,
            creator,
            context,
        };

        {
            let mut obligations = self.obligations.lock().unwrap();
            obligations.insert(obligation_id.clone(), info.clone());
        }

        self.notify_watchers(&info);

        tracing::debug!(
            "Created obligation: {} ({:?})",
            obligation_id,
            info.obligation_type
        );
        obligation_id
    }

    /// Update obligation state
    pub fn update_obligation(&self, obligation_id: &str, new_state: ObligationState) -> bool {
        let mut obligations = self.obligations.lock().unwrap();

        if let Some(info) = obligations.get_mut(obligation_id) {
            let old_state = info.state.clone();
            info.state = new_state.clone();
            info.last_updated = Instant::now();

            tracing::debug!(
                "Obligation {} state changed: {:?} -> {:?}",
                obligation_id,
                old_state,
                new_state
            );

            let info_clone = info.clone();
            drop(obligations); // Release lock before notifying

            self.notify_watchers(&info_clone);

            // Remove fulfilled or cancelled obligations
            if matches!(
                new_state,
                ObligationState::Fulfilled | ObligationState::Cancelled
            ) {
                let mut obligations = self.obligations.lock().unwrap();
                obligations.remove(obligation_id);
            }

            true
        } else {
            tracing::warn!(
                "Attempted to update non-existent obligation: {}",
                obligation_id
            );
            false
        }
    }

    /// Fulfill obligation
    pub fn fulfill_obligation(&self, obligation_id: &str) -> bool {
        self.update_obligation(obligation_id, ObligationState::Fulfilled)
    }

    /// Cancel obligation
    pub fn cancel_obligation(&self, obligation_id: &str) -> bool {
        self.update_obligation(obligation_id, ObligationState::Cancelled)
    }

    /// Check for obligation leaks
    pub fn check_for_leaks(&self, max_age: Duration) -> Vec<ObligationInfo> {
        if !self.leak_detection_enabled {
            return Vec::new();
        }

        let now = Instant::now();
        let obligations = self.obligations.lock().unwrap();
        let mut leaked = Vec::new();

        for (_, info) in obligations.iter() {
            let age = now.duration_since(info.created_at);

            if age > max_age
                && matches!(
                    info.state,
                    ObligationState::Active | ObligationState::Fulfilling
                )
            {
                tracing::error!(
                    "Obligation leak detected: {} ({:?}) - age: {:?}",
                    info.obligation_id,
                    info.obligation_type,
                    age
                );

                let mut leaked_info = info.clone();
                leaked_info.state = ObligationState::Leaked;
                leaked.push(leaked_info.clone());

                // Notify watchers of leak
                for watcher in self.watchers.lock().unwrap().iter() {
                    if let Some(watcher) = watcher.upgrade() {
                        watcher.on_leak_detected(&leaked_info);
                    }
                }
            }
        }

        leaked
    }

    /// Get current obligation count
    pub fn obligation_count(&self) -> usize {
        self.obligations.lock().unwrap().len()
    }

    /// Get obligations by type
    pub fn obligations_by_type(&self, obligation_type: &ObligationType) -> Vec<ObligationInfo> {
        self.obligations
            .lock()
            .unwrap()
            .values()
            .filter(|info| &info.obligation_type == obligation_type)
            .cloned()
            .collect()
    }

    /// Get all active obligations
    pub fn active_obligations(&self) -> Vec<ObligationInfo> {
        self.obligations
            .lock()
            .unwrap()
            .values()
            .filter(|info| {
                matches!(
                    info.state,
                    ObligationState::Active | ObligationState::Fulfilling
                )
            })
            .cloned()
            .collect()
    }

    /// Clear all obligations (for testing)
    pub fn clear_obligations(&self) {
        let mut obligations = self.obligations.lock().unwrap();
        tracing::info!("Clearing {} obligations", obligations.len());
        obligations.clear();
    }

    /// Add obligation watcher
    pub fn add_watcher(&self, watcher: Arc<dyn ObligationWatcher>) {
        let mut watchers = self.watchers.lock().unwrap();
        watchers.push(Arc::downgrade(&watcher));
    }

    /// Enable/disable leak detection
    pub fn set_leak_detection(&mut self, enabled: bool) {
        self.leak_detection_enabled = enabled;
    }

    /// Validate region quiescence
    pub fn validate_region_quiescence(&self) -> Result<(), ObligationLeakError> {
        let worker_count = self.count_active_workers();
        if worker_count > 0 {
            return Err(ObligationLeakError {
                leaked_count: worker_count,
                leak_details: vec![format!("{} active workers remaining", worker_count)],
            });
        }

        let active = self.active_obligations();

        if !active.is_empty() {
            let leak_details: Vec<String> = active
                .iter()
                .map(|info| format!("{} ({:?})", info.obligation_id, info.obligation_type))
                .collect();

            return Err(ObligationLeakError {
                leaked_count: active.len(),
                leak_details,
            });
        }

        Ok(())
    }

    /// Count worker obligations that still represent live workers.
    fn count_active_workers(&self) -> usize {
        self.obligations
            .lock()
            .unwrap()
            .values()
            .filter(|info| {
                matches!(&info.obligation_type, ObligationType::Worker(_))
                    && matches!(
                        &info.state,
                        ObligationState::Active | ObligationState::Fulfilling
                    )
            })
            .count()
    }

    /// Notify all watchers
    fn notify_watchers(&self, info: &ObligationInfo) {
        let watchers = self.watchers.lock().unwrap();
        for watcher in watchers.iter() {
            if let Some(watcher) = watcher.upgrade() {
                watcher.on_obligation_changed(info);
            }
        }
    }
}

impl Default for AtpObligationTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Error type for obligation leaks
#[derive(Debug)]
pub struct ObligationLeakError {
    pub leaked_count: usize,
    pub leak_details: Vec<String>,
}

impl std::fmt::Display for ObligationLeakError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Obligation leak detected: {} leaked obligations/workers: {}",
            self.leaked_count,
            self.leak_details.join(", ")
        )
    }
}

impl std::error::Error for ObligationLeakError {}

/// RAII obligation guard that automatically fulfills obligation when dropped
pub struct ObligationGuard {
    obligation_id: String,
    tracker: Arc<AtpObligationTracker>,
    auto_fulfill: bool,
}

impl ObligationGuard {
    /// Create new obligation guard
    pub fn new(
        tracker: Arc<AtpObligationTracker>,
        obligation_type: ObligationType,
        creator: String,
        context: HashMap<String, String>,
    ) -> Self {
        let obligation_id = tracker.create_obligation(obligation_type, creator, context);

        Self {
            obligation_id,
            tracker,
            auto_fulfill: true,
        }
    }

    /// Get obligation ID
    pub fn obligation_id(&self) -> &str {
        &self.obligation_id
    }

    /// Manually fulfill obligation
    pub fn fulfill(mut self) {
        self.tracker.fulfill_obligation(&self.obligation_id);
        self.auto_fulfill = false;
    }

    /// Cancel obligation
    pub fn cancel(mut self) {
        self.tracker.cancel_obligation(&self.obligation_id);
        self.auto_fulfill = false;
    }

    /// Disable auto-fulfill on drop
    pub fn disable_auto_fulfill(&mut self) {
        self.auto_fulfill = false;
    }
}

impl Drop for ObligationGuard {
    fn drop(&mut self) {
        if self.auto_fulfill {
            self.tracker.fulfill_obligation(&self.obligation_id);
        }
    }
}

/// Test-specific obligation watcher
pub struct TestObligationWatcher {
    name: String,
    changes: Arc<Mutex<Vec<ObligationInfo>>>,
    leaks: Arc<Mutex<Vec<ObligationInfo>>>,
}

impl TestObligationWatcher {
    pub fn new(name: String) -> Arc<Self> {
        Arc::new(Self {
            name,
            changes: Arc::new(Mutex::new(Vec::new())),
            leaks: Arc::new(Mutex::new(Vec::new())),
        })
    }

    pub fn changes(&self) -> Vec<ObligationInfo> {
        self.changes.lock().unwrap().clone()
    }

    pub fn leaks(&self) -> Vec<ObligationInfo> {
        self.leaks.lock().unwrap().clone()
    }

    pub fn clear(&self) {
        self.changes.lock().unwrap().clear();
        self.leaks.lock().unwrap().clear();
    }
}

impl ObligationWatcher for TestObligationWatcher {
    fn on_obligation_changed(&self, info: &ObligationInfo) {
        tracing::debug!(
            "[{}] Obligation changed: {} -> {:?}",
            self.name,
            info.obligation_id,
            info.state
        );
        self.changes.lock().unwrap().push(info.clone());
    }

    fn on_leak_detected(&self, info: &ObligationInfo) {
        tracing::error!(
            "[{}] Leak detected: {} ({:?})",
            self.name,
            info.obligation_id,
            info.obligation_type
        );
        self.leaks.lock().unwrap().push(info.clone());
    }
}

// Helper functions

fn generate_obligation_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("obl_{:08x}", id)
}

/// Global obligation tracker for testing
static GLOBAL_TRACKER: OnceLock<Arc<AtpObligationTracker>> = OnceLock::new();

/// Get global obligation tracker
pub fn global_obligation_tracker() -> Arc<AtpObligationTracker> {
    GLOBAL_TRACKER
        .get_or_init(|| Arc::new(AtpObligationTracker::new()))
        .clone()
}

/// Macro for creating obligation guards
#[macro_export]
macro_rules! obligation_guard {
    ($type:expr, $creator:expr) => {
        $crate::tests::atp::obligation_tracking::ObligationGuard::new(
            $crate::tests::atp::obligation_tracking::global_obligation_tracker(),
            $type,
            $creator.to_string(),
            std::collections::HashMap::new(),
        )
    };
    ($type:expr, $creator:expr, $context:expr) => {
        $crate::tests::atp::obligation_tracking::ObligationGuard::new(
            $crate::tests::atp::obligation_tracking::global_obligation_tracker(),
            $type,
            $creator.to_string(),
            $context,
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_obligation_creation_and_fulfillment() {
        let tracker = Arc::new(AtpObligationTracker::new());

        let obligation_id = tracker.create_obligation(
            ObligationType::Transfer("test".to_string()),
            "test_creator".to_string(),
            HashMap::new(),
        );

        assert_eq!(tracker.obligation_count(), 1);

        let fulfilled = tracker.fulfill_obligation(&obligation_id);
        assert!(fulfilled);
        assert_eq!(tracker.obligation_count(), 0);
    }

    #[test]
    fn test_obligation_guard() {
        let tracker = Arc::new(AtpObligationTracker::new());

        {
            let _guard = ObligationGuard::new(
                tracker.clone(),
                ObligationType::Transfer("test".to_string()),
                "test_creator".to_string(),
                HashMap::new(),
            );

            assert_eq!(tracker.obligation_count(), 1);
        } // Guard drops here, auto-fulfilling obligation

        assert_eq!(tracker.obligation_count(), 0);
    }

    #[test]
    fn test_leak_detection() {
        let tracker = Arc::new(AtpObligationTracker::new());

        let _obligation_id = tracker.create_obligation(
            ObligationType::Transfer("test".to_string()),
            "test_creator".to_string(),
            HashMap::new(),
        );

        // Check for leaks with very short timeout
        let leaks = tracker.check_for_leaks(Duration::from_nanos(1));
        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0].state, ObligationState::Leaked);
    }

    #[test]
    fn test_obligation_watcher() {
        let tracker = Arc::new(AtpObligationTracker::new());
        let watcher = TestObligationWatcher::new("test_watcher".to_string());

        tracker.add_watcher(watcher.clone());

        let obligation_id = tracker.create_obligation(
            ObligationType::Transfer("test".to_string()),
            "test_creator".to_string(),
            HashMap::new(),
        );

        tracker.fulfill_obligation(&obligation_id);

        let changes = watcher.changes();
        assert_eq!(changes.len(), 2); // Creation + fulfillment
    }

    #[test]
    fn test_region_quiescence_validation() {
        let tracker = Arc::new(AtpObligationTracker::new());

        // Should pass when no obligations
        assert!(tracker.validate_region_quiescence().is_ok());

        // Create active obligation
        let _obligation_id = tracker.create_obligation(
            ObligationType::Transfer("test".to_string()),
            "test_creator".to_string(),
            HashMap::new(),
        );

        // Should fail with active obligation
        assert!(tracker.validate_region_quiescence().is_err());
    }

    #[test]
    fn test_region_quiescence_reports_live_worker_obligations() {
        let tracker = Arc::new(AtpObligationTracker::new());

        let worker_id = tracker.create_obligation(
            ObligationType::Worker("repair-worker-0".to_string()),
            "worker_pool".to_string(),
            HashMap::new(),
        );

        assert_eq!(tracker.count_active_workers(), 1);
        let err = tracker
            .validate_region_quiescence()
            .expect_err("live worker obligation should block quiescence");
        assert_eq!(err.leaked_count, 1);
        assert_eq!(
            err.leak_details,
            vec!["1 active workers remaining".to_string()]
        );

        assert!(tracker.fulfill_obligation(&worker_id));
        assert_eq!(tracker.count_active_workers(), 0);
        assert!(tracker.validate_region_quiescence().is_ok());
    }
}
