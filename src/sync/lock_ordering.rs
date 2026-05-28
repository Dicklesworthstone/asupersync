//! Runtime lock ordering enforcement for deadlock prevention.
//!
//! Implements the asupersync lock hierarchy: E(Config) -> D(Instrumentation) -> B(Regions) -> A(Tasks) -> C(Obligations).
//! In debug builds or with `lock-metrics` feature, tracks lock acquisition order per thread and panics on violations.
//! In release builds without `lock-metrics`, all checks are compiled away for zero cost.
//!
//! # Cross-Module Enforcement
//!
//! Beyond basic rank ordering, this module enforces cross-module lock acquisition patterns
//! to prevent deadlocks when operations span multiple asupersync modules. Each lock is
//! tagged with both its rank and module, enabling detection of problematic cross-module patterns.

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
use std::cell::RefCell;
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
use std::collections::{BTreeMap, BTreeSet};

/// Lock rank categories following the asupersync hierarchy.
/// Lower numeric values must be acquired before higher values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LockRank {
    /// E: Configuration locks (lowest rank, acquired first)
    Config = 10,
    /// D: Instrumentation and metrics locks
    Instrumentation = 20,
    /// B: Region management locks
    Regions = 30,
    /// A: Task scheduling and state locks
    Tasks = 40,
    /// C: Obligation tracking locks (highest rank, acquired last)
    Obligations = 50,
}

/// Asupersync module identification for cross-module lock tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LockModule {
    /// Core runtime module (scheduler, regions, tasks)
    Runtime,
    /// Synchronization primitives module
    Sync,
    /// Capability context module
    Cx,
    /// Cancellation protocol module
    Cancel,
    /// Obligation tracking module
    Obligation,
    /// Channel and messaging modules
    Channel,
    /// I/O and networking modules
    Io,
    /// Other/unknown modules
    Other,
}

/// One deterministic lock-order edge observed by the atlas.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LockOrderEdge {
    /// Lock already held when the edge was observed.
    pub held_lock_name: String,
    /// Rank of the already-held lock.
    pub held_rank: LockRank,
    /// Module of the already-held lock.
    pub held_module: LockModule,
    /// Lock being acquired.
    pub acquired_lock_name: String,
    /// Rank of the lock being acquired.
    pub acquired_rank: LockRank,
    /// Module of the lock being acquired.
    pub acquired_module: LockModule,
}

/// One deterministic lock-order violation observed before enforcement panics.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LockOrderViolation {
    /// Lock whose acquisition violated the hierarchy.
    pub lock_name: String,
    /// Rank of the violating lock.
    pub lock_rank: LockRank,
    /// Module of the violating lock.
    pub lock_module: LockModule,
    /// Rank already held when the violation occurred.
    pub held_rank: LockRank,
    /// Stable violation reason for reports and tests.
    pub reason: String,
}

/// Deterministic lock-order atlas snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockOrderAtlasSnapshot {
    /// Exercised held-lock to acquired-lock order edges.
    pub order_edges_exercised: Vec<LockOrderEdge>,
    /// Violations recorded before enforcement panicked.
    pub order_violations: Vec<LockOrderViolation>,
    /// Instrumentation mode that produced the snapshot.
    pub instrumentation_mode: &'static str,
}

/// Information about an acquired lock for cross-module tracking.
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockInfo {
    /// Lock name recorded for ordering checks.
    pub name: String,
    /// Lock rank recorded for ordering checks.
    pub rank: LockRank,
    /// Lock module recorded for ordering checks.
    pub module: LockModule,
}

impl LockModule {
    /// Parse a lock module from a name or file path.
    pub fn from_name(name: &str) -> Self {
        if name.contains("runtime") || name.contains("scheduler") {
            LockModule::Runtime
        } else if name.contains("sync") || name.starts_with("mutex") || name.starts_with("rwlock") {
            LockModule::Sync
        } else if name.contains("cx") || name.contains("scope") || name.contains("macaroon") {
            LockModule::Cx
        } else if name.contains("cancel") || name.contains("progress") {
            LockModule::Cancel
        } else if name.contains("obligation") {
            LockModule::Obligation
        } else if name.contains("channel") || name.contains("mpsc") || name.contains("oneshot") {
            LockModule::Channel
        } else if name.contains("io") || name.contains("net") || name.contains("tcp") {
            LockModule::Io
        } else {
            LockModule::Other
        }
    }

    /// Get the name of this module for error messages.
    #[allow(dead_code)]
    pub fn name(self) -> &'static str {
        match self {
            LockModule::Runtime => "Runtime",
            LockModule::Sync => "Sync",
            LockModule::Cx => "Cx",
            LockModule::Cancel => "Cancel",
            LockModule::Obligation => "Obligation",
            LockModule::Channel => "Channel",
            LockModule::Io => "Io",
            LockModule::Other => "Other",
        }
    }
}

impl LockRank {
    /// Parse a lock rank from a name prefix.
    pub fn from_name(name: &str) -> Option<Self> {
        if name.starts_with("config") || name.starts_with("Config") {
            Some(LockRank::Config)
        } else if name.starts_with("metrics")
            || name.starts_with("instrumentation")
            || name.starts_with("trace")
        {
            Some(LockRank::Instrumentation)
        } else if name.starts_with("regions") || name.starts_with("region") {
            Some(LockRank::Regions)
        } else if name.starts_with("tasks")
            || name.starts_with("task")
            || name.starts_with("scheduler")
        {
            Some(LockRank::Tasks)
        } else if name.starts_with("obligations") || name.starts_with("obligation") {
            Some(LockRank::Obligations)
        } else {
            None // Unknown rank, no ordering enforced
        }
    }

    /// Get the name of this rank for error messages.
    #[allow(dead_code)]
    pub fn name(self) -> &'static str {
        match self {
            LockRank::Config => "Config",
            LockRank::Instrumentation => "Instrumentation",
            LockRank::Regions => "Regions",
            LockRank::Tasks => "Tasks",
            LockRank::Obligations => "Obligations",
        }
    }
}

/// Thread-local storage for tracking held lock ranks and modules.
/// Only compiled in debug builds.
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
thread_local! {
    static HELD_RANKS: RefCell<BTreeSet<LockRank>> = const { RefCell::new(BTreeSet::new()) };
    static HELD_LOCKS: RefCell<BTreeMap<LockRank, Vec<LockInfo>>> = const { RefCell::new(BTreeMap::new()) };
    static ORDER_EDGES: RefCell<BTreeSet<LockOrderEdge>> = const { RefCell::new(BTreeSet::new()) };
    static ORDER_VIOLATIONS: RefCell<Vec<LockOrderViolation>> = const { RefCell::new(Vec::new()) };
}

/// Check if acquiring a lock of the given rank would violate ordering.
/// In debug builds, panics on violations. In release builds, does nothing.
#[inline]
pub fn check_acquire(lock_name: &str, rank: LockRank) {
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    {
        check_acquire_with_module(lock_name, rank, LockModule::from_name(lock_name));
    }

    #[cfg(not(debug_assertions))]
    {
        let _ = (lock_name, rank); // Suppress unused variable warnings
    }
}

/// Check if acquiring a lock would violate ordering, with explicit module specification.
/// This is the enhanced version that performs cross-module validation.
#[inline]
pub fn check_acquire_with_module(lock_name: &str, rank: LockRank, module: LockModule) {
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    {
        HELD_RANKS.with(|held_ranks| {
            HELD_LOCKS.with(|held_locks| {
                let held_ranks_ref = held_ranks.borrow();
                let held_locks_ref = held_locks.borrow();

                record_order_edges(lock_name, rank, module, &held_locks_ref);

                // Basic rank ordering check
                if let Some(&highest_held) = held_ranks_ref.iter().last() {
                    if rank < highest_held {
                        record_order_violation(
                            lock_name,
                            rank,
                            module,
                            highest_held,
                            "rank-order",
                        );
                        panic!(
                            "DEADLOCK PREVENTION: Lock ordering violation!\n\
                            Attempted to acquire '{}' (rank {:?}, module {:?}) while holding locks of rank {:?}.\n\
                            Correct order: Config -> Instrumentation -> Regions -> Tasks -> Obligations\n\
                            This violates the asupersync lock hierarchy and could cause deadlocks.",
                            lock_name, rank, module, highest_held
                        );
                    }
                }

                // Cross-module pattern validation
                validate_cross_module_pattern(lock_name, rank, module, &held_locks_ref);
            });
        });
    }

    #[cfg(not(debug_assertions))]
    {
        let _ = (lock_name, rank, module); // Suppress unused variable warnings
    }
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
fn record_order_edges(
    lock_name: &str,
    rank: LockRank,
    module: LockModule,
    held_locks: &BTreeMap<LockRank, Vec<LockInfo>>,
) {
    ORDER_EDGES.with(|edges| {
        let mut edges = edges.borrow_mut();
        for locks_at_rank in held_locks.values() {
            for held in locks_at_rank {
                edges.insert(LockOrderEdge {
                    held_lock_name: held.name.clone(), // ubs:ignore - debug diagnostic allocation
                    held_rank: held.rank,
                    held_module: held.module,
                    acquired_lock_name: lock_name.to_string(),
                    acquired_rank: rank,
                    acquired_module: module,
                });
            }
        }
    });
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
fn record_order_violation(
    lock_name: &str,
    rank: LockRank,
    module: LockModule,
    held_rank: LockRank,
    reason: &'static str,
) {
    ORDER_VIOLATIONS.with(|violations| {
        violations.borrow_mut().push(LockOrderViolation {
            lock_name: lock_name.to_string(),
            lock_rank: rank,
            lock_module: module,
            held_rank,
            reason: reason.to_string(),
        });
    });
}

/// Validate cross-module lock acquisition patterns to prevent complex deadlocks.
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
fn validate_cross_module_pattern(
    lock_name: &str,
    rank: LockRank,
    module: LockModule,
    held_locks: &BTreeMap<LockRank, Vec<LockInfo>>,
) {
    // Rule 1: Obligations module locks should not be acquired while holding Cancel module locks
    // (prevents obligation tracking from deadlocking with cancellation)
    if module == LockModule::Obligation && rank == LockRank::Obligations {
        for locks_at_rank in held_locks.values() {
            for lock_info in locks_at_rank {
                if lock_info.module == LockModule::Cancel {
                    record_order_violation(
                        lock_name,
                        rank,
                        module,
                        lock_info.rank,
                        "cancel-before-obligation",
                    );
                    panic!(
                        "CROSS-MODULE DEADLOCK PREVENTION: Attempted to acquire obligation lock '{}' \
                        while holding cancel module lock '{}'. This pattern can cause deadlocks \
                        between cancellation and obligation tracking.",
                        lock_name, lock_info.name
                    );
                }
            }
        }
    }

    // Rule 2: Cx module locks should be acquired before Cancel module locks
    // (capability contexts must be established before cancellation operations)
    if module == LockModule::Cancel {
        for (held_rank, locks_at_rank) in held_locks {
            for lock_info in locks_at_rank {
                if lock_info.module == LockModule::Cx && *held_rank > rank {
                    record_order_violation(lock_name, rank, module, *held_rank, "cx-before-cancel");
                    panic!(
                        "CROSS-MODULE DEADLOCK PREVENTION: Attempted to acquire cancel lock '{}' (rank {:?}) \
                        while holding higher-ranked Cx lock '{}' (rank {:?}). \
                        Capability context operations must complete before cancellation.",
                        lock_name, rank, lock_info.name, held_rank
                    );
                }
            }
        }
    }

    // Rule 3: Runtime module locks should be acquired in a specific order relative to other modules
    // (scheduler state must be consistent with obligation state)
    if module == LockModule::Runtime && rank == LockRank::Tasks {
        for locks_at_rank in held_locks.values() {
            for lock_info in locks_at_rank {
                if lock_info.module == LockModule::Obligation
                    && lock_info.rank == LockRank::Obligations
                {
                    record_order_violation(
                        lock_name,
                        rank,
                        module,
                        lock_info.rank,
                        "obligation-before-runtime-task",
                    );
                    panic!(
                        "CROSS-MODULE DEADLOCK PREVENTION: Attempted to acquire task lock '{}' \
                        while holding obligation lock '{}'. Task scheduling must be coordinated \
                        with obligation tracking to prevent state inconsistencies.",
                        lock_name, lock_info.name
                    );
                }
            }
        }
    }
}

/// Record that a lock of the given rank has been acquired.
/// Only active in debug builds.
#[inline]
pub fn record_acquire(lock_name: &str, rank: LockRank) {
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    {
        record_acquire_with_module(lock_name, rank, LockModule::from_name(lock_name));
    }

    #[cfg(not(debug_assertions))]
    {
        let _ = (lock_name, rank); // Suppress unused variable warning
    }
}

/// Record that a lock has been acquired with full module information.
/// This is the enhanced version that tracks cross-module relationships.
#[inline]
pub fn record_acquire_with_module(lock_name: &str, rank: LockRank, module: LockModule) {
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    {
        HELD_RANKS.with(|held_ranks| {
            HELD_LOCKS.with(|held_locks| {
                held_ranks.borrow_mut().insert(rank);

                let lock_info = LockInfo {
                    name: lock_name.to_string(),
                    rank,
                    module,
                };

                held_locks
                    .borrow_mut()
                    .entry(rank)
                    .or_insert_with(Vec::new)
                    .push(lock_info);
            });
        });
    }

    #[cfg(not(debug_assertions))]
    {
        let _ = (lock_name, rank, module); // Suppress unused variable warnings
    }
}

/// Record that a lock of the given rank has been released.
/// Only active in debug builds.
#[inline]
pub fn record_release(lock_name: &str, rank: LockRank) {
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    {
        record_release_with_module(lock_name, rank, LockModule::from_name(lock_name));
    }

    #[cfg(not(debug_assertions))]
    {
        let _ = (lock_name, rank); // Suppress unused variable warning
    }
}

/// Record that a specific lock has been released with full module information.
/// This is the enhanced version that maintains cross-module tracking accuracy.
#[inline]
pub fn record_release_with_module(lock_name: &str, rank: LockRank, module: LockModule) {
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    {
        HELD_RANKS.with(|held_ranks| {
            HELD_LOCKS.with(|held_locks| {
                let mut held_locks_mut = held_locks.borrow_mut();

                if let Some(locks_at_rank) = held_locks_mut.get_mut(&rank) {
                    // Remove the specific lock by name and module
                    locks_at_rank.retain(|lock| !(lock.name == lock_name && lock.module == module));

                    // If no more locks at this rank, remove the rank entirely
                    if locks_at_rank.is_empty() {
                        held_locks_mut.remove(&rank);
                        held_ranks.borrow_mut().remove(&rank);
                    }
                }
            });
        });
    }

    #[cfg(not(debug_assertions))]
    {
        let _ = (lock_name, rank, module); // Suppress unused variable warnings
    }
}

/// Get the currently held lock ranks for debugging.
/// Only available in debug builds.
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
#[allow(dead_code)]
pub fn current_held_ranks() -> Vec<LockRank> {
    HELD_RANKS.with(|held| held.borrow().iter().copied().collect())
}

/// Get detailed information about all currently held locks for debugging.
/// Only available in debug builds.
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
#[allow(dead_code)]
pub fn current_held_locks() -> BTreeMap<LockRank, Vec<LockInfo>> {
    HELD_LOCKS.with(|held| held.borrow().clone())
}

/// Clear all held lock tracking (for testing purposes only).
/// Only available in debug builds.
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
#[allow(dead_code)]
pub fn clear_held_locks() {
    HELD_RANKS.with(|held_ranks| held_ranks.borrow_mut().clear());
    HELD_LOCKS.with(|held_locks| held_locks.borrow_mut().clear());
    clear_lock_order_atlas();
}

/// Return the current deterministic lock-order atlas snapshot.
#[must_use]
pub fn lock_order_atlas_snapshot() -> LockOrderAtlasSnapshot {
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    {
        let order_edges_exercised =
            ORDER_EDGES.with(|edges| edges.borrow().iter().cloned().collect());
        let order_violations = ORDER_VIOLATIONS.with(|violations| violations.borrow().clone());

        LockOrderAtlasSnapshot {
            order_edges_exercised,
            order_violations,
            instrumentation_mode: "debug_lock_ordering",
        }
    }

    #[cfg(not(any(debug_assertions, feature = "lock-metrics")))]
    {
        LockOrderAtlasSnapshot {
            order_edges_exercised: Vec::new(),
            order_violations: Vec::new(),
            instrumentation_mode: "disabled",
        }
    }
}

/// Clear deterministic lock-order atlas state for the current thread.
pub fn clear_lock_order_atlas() {
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    {
        ORDER_EDGES.with(|edges| edges.borrow_mut().clear());
        ORDER_VIOLATIONS.with(|violations| violations.borrow_mut().clear());
    }
}

/// Enhanced API for Mutex to use cross-module lock ordering enforcement.
/// This replaces the basic check_acquire/record_acquire pattern with module-aware tracking.
#[allow(dead_code)]
pub struct LockOrderEnforcer {
    lock_name: String,
    rank: LockRank,
    module: LockModule,
}

impl LockOrderEnforcer {
    /// Create a new lock order enforcer for the given lock.
    #[allow(dead_code)]
    pub fn new(lock_name: &str, rank: LockRank) -> Self {
        let module = LockModule::from_name(lock_name);
        Self {
            lock_name: lock_name.to_string(),
            rank,
            module,
        }
    }

    /// Create a lock order enforcer with explicit module specification.
    #[allow(dead_code)]
    pub fn with_module(lock_name: &str, rank: LockRank, module: LockModule) -> Self {
        Self {
            lock_name: lock_name.to_string(),
            rank,
            module,
        }
    }

    /// Check if acquiring this lock would violate ordering and record the acquisition.
    #[allow(dead_code)]
    #[inline]
    pub fn acquire(&self) {
        check_acquire_with_module(&self.lock_name, self.rank, self.module);
        record_acquire_with_module(&self.lock_name, self.rank, self.module);
    }

    /// Record the release of this lock.
    #[allow(dead_code)]
    #[inline]
    pub fn release(&self) {
        record_release_with_module(&self.lock_name, self.rank, self.module);
    }

    /// Check if acquiring this lock would violate ordering (without recording).
    #[allow(dead_code)]
    #[inline]
    pub fn check_only(&self) {
        check_acquire_with_module(&self.lock_name, self.rank, self.module);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_rank_from_name() {
        assert_eq!(LockRank::from_name("config_cache"), Some(LockRank::Config));
        assert_eq!(
            LockRank::from_name("metrics_collector"),
            Some(LockRank::Instrumentation)
        );
        assert_eq!(
            LockRank::from_name("regions_table"),
            Some(LockRank::Regions)
        );
        assert_eq!(LockRank::from_name("tasks_queue"), Some(LockRank::Tasks));
        assert_eq!(
            LockRank::from_name("obligations_ledger"),
            Some(LockRank::Obligations)
        );
        assert_eq!(LockRank::from_name("unknown_lock"), None);
    }

    #[test]
    fn test_lock_rank_ordering() {
        assert!(LockRank::Config < LockRank::Instrumentation);
        assert!(LockRank::Instrumentation < LockRank::Regions);
        assert!(LockRank::Regions < LockRank::Tasks);
        assert!(LockRank::Tasks < LockRank::Obligations);
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn test_correct_lock_ordering() {
        // This should not panic - correct ordering
        check_acquire("config_test", LockRank::Config);
        record_acquire("config_test", LockRank::Config);

        check_acquire("regions_test", LockRank::Regions);
        record_acquire("regions_test", LockRank::Regions);

        check_acquire("tasks_test", LockRank::Tasks);
        record_acquire("tasks_test", LockRank::Tasks);

        record_release("tasks_test", LockRank::Tasks);
        record_release("regions_test", LockRank::Regions);
        record_release("config_test", LockRank::Config);
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[should_panic(expected = "Lock ordering violation")]
    fn test_incorrect_lock_ordering() {
        clear_held_locks(); // Start with clean state
        // This should panic - trying to acquire Config after Tasks
        record_acquire("tasks_test", LockRank::Tasks);
        check_acquire("config_test", LockRank::Config); // This should panic
    }

    #[test]
    fn test_module_from_name() {
        assert_eq!(
            LockModule::from_name("runtime_scheduler"),
            LockModule::Runtime
        );
        assert_eq!(LockModule::from_name("sync_mutex"), LockModule::Sync);
        assert_eq!(LockModule::from_name("cx_scope"), LockModule::Cx);
        assert_eq!(LockModule::from_name("cancel_protocol"), LockModule::Cancel);
        assert_eq!(
            LockModule::from_name("obligation_tracker"),
            LockModule::Obligation
        );
        assert_eq!(LockModule::from_name("channel_mpsc"), LockModule::Channel);
        assert_eq!(LockModule::from_name("io_tcp"), LockModule::Io);
        assert_eq!(LockModule::from_name("unknown_module"), LockModule::Other);
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn test_cross_module_correct_patterns() {
        clear_held_locks(); // Start with clean state

        // This should work - Cx before Cancel
        check_acquire_with_module("cx_scope", LockRank::Regions, LockModule::Cx);
        record_acquire_with_module("cx_scope", LockRank::Regions, LockModule::Cx);

        check_acquire_with_module("cancel_token", LockRank::Obligations, LockModule::Cancel);
        record_acquire_with_module("cancel_token", LockRank::Obligations, LockModule::Cancel);

        // Clean up
        record_release_with_module("cancel_token", LockRank::Obligations, LockModule::Cancel);
        record_release_with_module("cx_scope", LockRank::Regions, LockModule::Cx);
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[should_panic(expected = "CROSS-MODULE DEADLOCK PREVENTION")]
    fn test_cross_module_obligation_cancel_violation() {
        clear_held_locks(); // Start with clean state

        // Hold a Cancel module lock
        record_acquire_with_module("cancel_token", LockRank::Tasks, LockModule::Cancel);

        // This should panic - acquiring Obligation lock while holding Cancel lock
        check_acquire_with_module(
            "obligation_tracker",
            LockRank::Obligations,
            LockModule::Obligation,
        );
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[should_panic(expected = "CROSS-MODULE DEADLOCK PREVENTION")]
    fn test_cross_module_cx_cancel_violation() {
        clear_held_locks(); // Start with clean state

        // Hold a higher-ranked Cx lock
        record_acquire_with_module("cx_macaroon", LockRank::Obligations, LockModule::Cx);

        // This should panic - acquiring lower-ranked Cancel lock while holding higher-ranked Cx lock
        check_acquire_with_module("cancel_token", LockRank::Tasks, LockModule::Cancel);
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    #[should_panic(expected = "CROSS-MODULE DEADLOCK PREVENTION")]
    fn test_cross_module_runtime_obligation_violation() {
        clear_held_locks(); // Start with clean state

        // Hold an Obligation lock
        record_acquire_with_module(
            "obligation_ledger",
            LockRank::Obligations,
            LockModule::Obligation,
        );

        // This should panic - acquiring Task lock while holding Obligation lock
        check_acquire_with_module("runtime_tasks", LockRank::Tasks, LockModule::Runtime);
    }

    #[test]
    #[cfg(any(debug_assertions, feature = "lock-metrics"))]
    fn test_detailed_lock_tracking() {
        clear_held_locks(); // Start with clean state

        // Acquire multiple locks
        record_acquire_with_module("config_cache", LockRank::Config, LockModule::Runtime);
        record_acquire_with_module("sync_mutex", LockRank::Tasks, LockModule::Sync);

        let held_locks = current_held_locks();
        assert_eq!(held_locks.len(), 2);

        assert!(held_locks.contains_key(&LockRank::Config));
        assert!(held_locks.contains_key(&LockRank::Tasks));

        let config_locks = &held_locks[&LockRank::Config];
        assert_eq!(config_locks.len(), 1);
        assert_eq!(config_locks[0].name, "config_cache");
        assert_eq!(config_locks[0].module, LockModule::Runtime);

        // Clean up
        record_release_with_module("sync_mutex", LockRank::Tasks, LockModule::Sync);
        record_release_with_module("config_cache", LockRank::Config, LockModule::Runtime);

        let held_locks_after = current_held_locks();
        assert_eq!(held_locks_after.len(), 0);
    }
}
