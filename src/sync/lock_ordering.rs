//! Runtime lock ordering enforcement for deadlock prevention.
//!
//! Implements the asupersync lock hierarchy: E(Config) -> D(Instrumentation) -> B(Regions) -> A(Tasks) -> C(Obligations).
//! In debug builds, tracks lock acquisition order per thread and panics on violations.
//! In release builds, all checks are compiled away for zero cost.

use std::cell::RefCell;
use std::collections::BTreeSet;

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

/// Thread-local storage for tracking held lock ranks.
/// Only compiled in debug builds.
#[cfg(debug_assertions)]
thread_local! {
    static HELD_RANKS: RefCell<BTreeSet<LockRank>> = RefCell::new(BTreeSet::new());
}

/// Check if acquiring a lock of the given rank would violate ordering.
/// In debug builds, panics on violations. In release builds, does nothing.
#[inline]
pub fn check_acquire(lock_name: &str, rank: LockRank) {
    #[cfg(debug_assertions)]
    {
        HELD_RANKS.with(|held| {
            let held_ref = held.borrow();

            // Check if we're trying to acquire a rank lower than any currently held
            if let Some(&highest_held) = held_ref.iter().last() {
                if rank < highest_held {
                    panic!(
                        "DEADLOCK PREVENTION: Lock ordering violation!\n\
                        Attempted to acquire '{}' (rank {:?}) while holding locks of rank {:?}.\n\
                        Correct order: Config -> Instrumentation -> Regions -> Tasks -> Obligations\n\
                        This violates the asupersync lock hierarchy and could cause deadlocks.",
                        lock_name, rank, highest_held
                    );
                }
            }
        });
    }

    #[cfg(not(debug_assertions))]
    {
        let _ = (lock_name, rank); // Suppress unused variable warnings
    }
}

/// Record that a lock of the given rank has been acquired.
/// Only active in debug builds.
#[inline]
pub fn record_acquire(rank: LockRank) {
    #[cfg(debug_assertions)]
    {
        HELD_RANKS.with(|held| {
            held.borrow_mut().insert(rank);
        });
    }

    #[cfg(not(debug_assertions))]
    {
        let _ = rank; // Suppress unused variable warning
    }
}

/// Record that a lock of the given rank has been released.
/// Only active in debug builds.
#[inline]
pub fn record_release(rank: LockRank) {
    #[cfg(debug_assertions)]
    {
        HELD_RANKS.with(|held| {
            held.borrow_mut().remove(&rank);
        });
    }

    #[cfg(not(debug_assertions))]
    {
        let _ = rank; // Suppress unused variable warning
    }
}

/// Get the currently held lock ranks for debugging.
/// Only available in debug builds.
#[cfg(debug_assertions)]
#[allow(dead_code)]
pub fn current_held_ranks() -> Vec<LockRank> {
    HELD_RANKS.with(|held| held.borrow().iter().copied().collect())
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
    #[cfg(debug_assertions)]
    fn test_correct_lock_ordering() {
        // This should not panic - correct ordering
        check_acquire("config_test", LockRank::Config);
        record_acquire(LockRank::Config);

        check_acquire("regions_test", LockRank::Regions);
        record_acquire(LockRank::Regions);

        check_acquire("tasks_test", LockRank::Tasks);
        record_acquire(LockRank::Tasks);

        record_release(LockRank::Tasks);
        record_release(LockRank::Regions);
        record_release(LockRank::Config);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Lock ordering violation")]
    fn test_incorrect_lock_ordering() {
        // This should panic - trying to acquire Config after Tasks
        record_acquire(LockRank::Tasks);
        check_acquire("config_test", LockRank::Config); // This should panic
    }
}
