//! Identifier types for runtime entities.
//!
//! These types provide type-safe identifiers for the core runtime entities:
//! regions, tasks, and obligations. They wrap arena indices with type safety.

use crate::util::ArenaIndex;
use core::fmt;

/// A unique identifier for a region in the runtime.
///
/// Regions form a tree structure and own all work spawned within them.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RegionId(pub(crate) ArenaIndex);

impl RegionId {
    /// Creates a new region ID from an arena index (internal use).
    #[must_use]
    pub(crate) const fn from_arena(index: ArenaIndex) -> Self {
        Self(index)
    }

    /// Returns the underlying arena index (internal use).
    #[must_use]
    #[allow(dead_code)]
    pub(crate) const fn arena_index(self) -> ArenaIndex {
        self.0
    }
}

impl fmt::Debug for RegionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RegionId({}:{})", self.0.index(), self.0.generation())
    }
}

impl fmt::Display for RegionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "R{}", self.0.index())
    }
}

/// A unique identifier for a task in the runtime.
///
/// Tasks are units of concurrent execution owned by regions.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TaskId(pub(crate) ArenaIndex);

impl TaskId {
    /// Creates a new task ID from an arena index (internal use).
    #[must_use]
    #[allow(dead_code)]
    pub(crate) const fn from_arena(index: ArenaIndex) -> Self {
        Self(index)
    }

    /// Returns the underlying arena index (internal use).
    #[must_use]
    #[allow(dead_code)]
    pub(crate) const fn arena_index(self) -> ArenaIndex {
        self.0
    }
}

impl fmt::Debug for TaskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TaskId({}:{})", self.0.index(), self.0.generation())
    }
}

impl fmt::Display for TaskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "T{}", self.0.index())
    }
}

/// A unique identifier for an obligation in the runtime.
///
/// Obligations represent resources that must be resolved (commit, abort, ack, etc.)
/// before their owning region can close.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObligationId(pub(crate) ArenaIndex);

impl ObligationId {
    /// Creates a new obligation ID from an arena index (internal use).
    #[must_use]
    #[allow(dead_code)]
    pub(crate) const fn from_arena(index: ArenaIndex) -> Self {
        Self(index)
    }

    /// Returns the underlying arena index (internal use).
    #[must_use]
    #[allow(dead_code)]
    pub(crate) const fn arena_index(self) -> ArenaIndex {
        self.0
    }
}

impl fmt::Debug for ObligationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ObligationId({}:{})",
            self.0.index(),
            self.0.generation()
        )
    }
}

impl fmt::Display for ObligationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "O{}", self.0.index())
    }
}

/// A logical timestamp for the runtime.
///
/// In the production runtime, this corresponds to wall-clock time.
/// In the lab runtime, this is virtual time controlled by the scheduler.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Time(u64);

impl Time {
    /// The zero instant (epoch).
    pub const ZERO: Self = Self(0);

    /// The maximum representable instant.
    pub const MAX: Self = Self(u64::MAX);

    /// Creates a new time from nanoseconds since epoch.
    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    /// Creates a new time from milliseconds since epoch.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis.saturating_mul(1_000_000))
    }

    /// Creates a new time from seconds since epoch.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs.saturating_mul(1_000_000_000))
    }

    /// Returns the time as nanoseconds since epoch.
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// Returns the time as milliseconds since epoch (truncated).
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0 / 1_000_000
    }

    /// Returns the time as seconds since epoch (truncated).
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0 / 1_000_000_000
    }

    /// Adds a duration in nanoseconds, saturating on overflow.
    #[must_use]
    pub const fn saturating_add_nanos(self, nanos: u64) -> Self {
        Self(self.0.saturating_add(nanos))
    }

    /// Subtracts a duration in nanoseconds, saturating at zero.
    #[must_use]
    pub const fn saturating_sub_nanos(self, nanos: u64) -> Self {
        Self(self.0.saturating_sub(nanos))
    }

    /// Returns the duration between two times in nanoseconds.
    ///
    /// Returns 0 if `self` is before `earlier`.
    #[must_use]
    pub const fn duration_since(self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

impl fmt::Debug for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Time({}ns)", self.0)
    }
}

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 >= 1_000_000_000 {
            write!(
                f,
                "{}.{:03}s",
                self.0 / 1_000_000_000,
                (self.0 / 1_000_000) % 1000
            )
        } else if self.0 >= 1_000_000 {
            write!(f, "{}ms", self.0 / 1_000_000)
        } else if self.0 >= 1_000 {
            write!(f, "{}us", self.0 / 1_000)
        } else {
            write!(f, "{}ns", self.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_conversions() {
        assert_eq!(Time::from_secs(1).as_nanos(), 1_000_000_000);
        assert_eq!(Time::from_millis(1).as_nanos(), 1_000_000);
        assert_eq!(Time::from_nanos(1).as_nanos(), 1);

        assert_eq!(Time::from_nanos(1_500_000_000).as_secs(), 1);
        assert_eq!(Time::from_nanos(1_500_000_000).as_millis(), 1500);
    }

    #[test]
    fn time_arithmetic() {
        let t1 = Time::from_secs(1);
        let t2 = t1.saturating_add_nanos(500_000_000);
        assert_eq!(t2.as_millis(), 1500);

        let t3 = t2.saturating_sub_nanos(2_000_000_000);
        assert_eq!(t3, Time::ZERO);
    }

    #[test]
    fn time_ordering() {
        assert!(Time::from_secs(1) < Time::from_secs(2));
        assert!(Time::from_millis(1000) == Time::from_secs(1));
    }
}
