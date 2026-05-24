//! Identifier types for runtime entities.
//!
//! These types provide type-safe identifiers for the core runtime entities:
//! regions, tasks, and obligations. They wrap arena indices with type safety.

use crate::util::ArenaIndex;
use core::fmt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::ops::Add;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

/// br-asupersync-u3gsst — Process-global ephemeral counters.
///
/// These back the test/test-internals-gated `new_ephemeral` constructors
/// and the runtime-internal `next_bootstrap_*` helpers used during root-Cx
/// boot in `app.rs`. They are NOT a substitute for runtime-allocated IDs
/// produced by `Arena::insert`; those are the only IDs that appear in
/// per-runtime-state structures, get registered with the scheduler, and
/// participate in deterministic replay.
static EPHEMERAL_REGION_COUNTER: AtomicU32 = AtomicU32::new(1);
static EPHEMERAL_TASK_COUNTER: AtomicU32 = AtomicU32::new(1);

/// br-asupersync-u3gsst — Mint a new bootstrap RegionId outside the
/// runtime's arena. **Crate-internal only**; intended for the single
/// production call-site in `app.rs::build_app_root_cx` that needs an ID
/// before the runtime has registered the root region. All other
/// production paths must use the runtime-allocated ID returned by
/// `Arena::insert`.
#[inline]
#[must_use]
pub(crate) fn next_bootstrap_region_id() -> RegionId {
    let index = EPHEMERAL_REGION_COUNTER.fetch_add(1, Ordering::Relaxed);
    RegionId(ArenaIndex::new(index, 1))
}

/// br-asupersync-u3gsst — Mint a new bootstrap TaskId outside the
/// runtime's arena. Same contract as `next_bootstrap_region_id`.
#[inline]
#[must_use]
pub(crate) fn next_bootstrap_task_id() -> TaskId {
    let index = EPHEMERAL_TASK_COUNTER.fetch_add(1, Ordering::Relaxed);
    TaskId(ArenaIndex::new(index, 1))
}

/// A unique identifier for a region in the runtime.
///
/// Regions form a tree structure and own all work spawned within them.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RegionId(pub(crate) ArenaIndex);

impl RegionId {
    /// Creates a new region ID from an arena index (internal use).
    #[inline]
    #[must_use]
    #[cfg_attr(feature = "test-internals", visibility::make(pub))]
    pub(crate) const fn from_arena(index: ArenaIndex) -> Self {
        Self(index)
    }

    /// Returns a 64-bit integer representation of this RegionId.
    #[inline]
    #[must_use]
    pub fn as_u64(&self) -> u64 {
        ((self.0.generation() as u64) << 32) | (self.0.index() as u64)
    }

    /// Returns the underlying arena index (internal use).
    #[inline]
    #[must_use]
    #[allow(dead_code)]
    #[cfg(not(feature = "test-internals"))]
    pub(crate) const fn arena_index(self) -> ArenaIndex {
        self.0
    }

    /// Returns the underlying arena index (internal use).
    #[inline]
    #[must_use]
    #[allow(dead_code)]
    #[cfg(feature = "test-internals")]
    pub const fn arena_index(self) -> ArenaIndex {
        self.0
    }

    /// Creates a region ID for testing/benchmarking purposes.
    ///
    /// br-asupersync-bm08jx: gated behind
    /// `cfg(any(test, feature = "test-internals"))` to prevent
    /// downstream production crates from forging RegionIds that
    /// match arbitrary runtime allocations. Pre-fix this was a
    /// fully-public `pub const` constructor (only `#[doc(hidden)]`
    /// for diagnostic discretion), so any external crate could mint
    /// a `RegionId` with arbitrary `index`/`generation` and feed it
    /// to runtime APIs that trust the ID shape — same threat model
    /// as the closed asupersync-aog0xz / asupersync-wm9h2a /
    /// asupersync-ovztin fixes for similar test-only constructors.
    ///
    /// Default-feature builds still see this constructor (the
    /// `test-internals` feature is in the default set, so existing
    /// test code keeps compiling); production crates that opt out via
    /// `default-features = false` lose access entirely.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-internals"))]
    #[inline]
    #[must_use]
    pub const fn new_for_test(index: u32, generation: u32) -> Self {
        Self(ArenaIndex::new(index, generation))
    }

    /// Creates a default region ID for testing purposes.
    ///
    /// This creates an ID with index 0 and generation 0, suitable for
    /// unit tests that don't care about specific ID values.
    #[doc(hidden)]
    #[inline]
    #[must_use]
    pub const fn testing_default() -> Self {
        Self(ArenaIndex::new(0, 0))
    }

    /// Creates a new ephemeral region ID outside the runtime arena.
    ///
    /// br-asupersync-u3gsst — **Test / test-internals only.** Production
    /// regions MUST be allocated by the runtime via
    /// [`crate::runtime::RuntimeState`] so the resulting `RegionId`
    /// appears in the region table, the lock-ordering invariants hold,
    /// and deterministic replay through [`crate::lab::LabRuntime`]
    /// observes the same IDs across runs. This constructor uses a
    /// process-global atomic counter and therefore breaks both
    /// invariants when called from production code; it is gated to
    /// `cfg(any(test, feature = "test-internals"))`. The single
    /// runtime-internal bootstrap call in `app.rs` uses the
    /// `pub(crate)` [`next_bootstrap_region_id`] instead.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-internals"))]
    #[inline]
    #[must_use]
    pub fn new_ephemeral() -> Self {
        next_bootstrap_region_id()
    }
}

impl fmt::Debug for RegionId {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RegionId({}:{})", self.0.index(), self.0.generation())
    }
}

impl fmt::Display for RegionId {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "R{}", self.0.index())
    }
}

/// br-asupersync-o2oa4l — Pre-shared per-type discriminant strings.
///
/// `RegionId`, `TaskId`, `ObligationId`, and `DecisionId` previously
/// shared a single `SerdeArenaIndex { index, generation }` wire shape
/// — every (index, generation) tuple deserialised equally well as
/// any of the four. An attacker submitting a snapshot or a peer
/// transmitting a trace artifact could swap an ID across the type
/// boundary by relabelling the JSON / MessagePack key, and the
/// deserialiser would have no way to reject the cross-type
/// confusion.
///
/// The new wire shape `SerdeIdEnvelope { kind, index, generation }`
/// stamps a stable per-type tag on serialise; deserialise verifies
/// the tag matches the target type and rejects with
/// `serde::de::Error::custom` otherwise. The four constants below
/// are the canonical tag values; they are stable across versions and
/// MUST NOT be reused for any other type without coordinating a
/// schema-version bump.
const KIND_REGION_ID: &str = "RegionId";
const KIND_TASK_ID: &str = "TaskId";
const KIND_OBLIGATION_ID: &str = "ObligationId";
// Note: DecisionId lives in `franken_kernel` and serialises as a hex
// u128 — its wire shape is already distinct from the SerdeArenaIndex
// triple here, so it does not need a discriminant tag.

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerdeIdEnvelope {
    kind: String,
    index: u32,
    generation: u32,
}

impl SerdeIdEnvelope {
    #[inline]
    fn from_arena(arena: ArenaIndex, kind: &'static str) -> Self {
        Self {
            kind: kind.to_string(),
            index: arena.index(),
            generation: arena.generation(),
        }
    }

    #[inline]
    fn to_arena(&self) -> ArenaIndex {
        ArenaIndex::new(self.index, self.generation)
    }

    #[inline]
    fn check_kind<E>(&self, expected: &'static str) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        if self.kind == expected {
            Ok(())
        } else {
            Err(E::custom(format!(
                "br-asupersync-o2oa4l: ID kind mismatch — expected {expected:?}, got {:?}",
                self.kind
            )))
        }
    }
}

impl Serialize for RegionId {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SerdeIdEnvelope::from_arena(self.0, KIND_REGION_ID).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RegionId {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let env = SerdeIdEnvelope::deserialize(deserializer)?;
        env.check_kind::<D::Error>(KIND_REGION_ID)?;
        Ok(Self(env.to_arena()))
    }
}

/// A unique identifier for a task in the runtime.
///
/// Tasks are units of concurrent execution owned by regions.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(pub(crate) ArenaIndex);

impl TaskId {
    /// Creates a new task ID from an arena index (internal use).
    #[inline]
    #[must_use]
    #[allow(dead_code)]
    #[cfg_attr(feature = "test-internals", visibility::make(pub))]
    pub(crate) const fn from_arena(index: ArenaIndex) -> Self {
        Self(index)
    }

    /// Returns a 64-bit integer representation of this `TaskId`.
    #[inline]
    #[must_use]
    pub fn as_u64(&self) -> u64 {
        ((self.0.generation() as u64) << 32) | (self.0.index() as u64)
    }

    /// Returns the underlying arena index (internal use).
    #[inline]
    #[must_use]
    #[allow(dead_code)]
    #[cfg(not(feature = "test-internals"))]
    pub(crate) const fn arena_index(self) -> ArenaIndex {
        self.0
    }

    /// Returns the underlying arena index (internal use).
    #[inline]
    #[must_use]
    #[allow(dead_code)]
    #[cfg(feature = "test-internals")]
    pub const fn arena_index(self) -> ArenaIndex {
        self.0
    }

    /// Creates a task ID for testing/benchmarking purposes.
    ///
    /// br-asupersync-bm08jx: gated behind
    /// `cfg(any(test, feature = "test-internals"))` — same rationale
    /// as [`RegionId::new_for_test`]. Production crates that disable
    /// `test-internals` lose access; the runtime's task arena is the
    /// only supported source of `TaskId`s.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-internals"))]
    #[inline]
    #[must_use]
    pub const fn new_for_test(index: u32, generation: u32) -> Self {
        Self(ArenaIndex::new(index, generation))
    }

    /// Creates a default task ID for testing purposes.
    ///
    /// This creates an ID with index 0 and generation 0, suitable for
    /// unit tests that don't care about specific ID values.
    #[doc(hidden)]
    #[inline]
    #[must_use]
    pub const fn testing_default() -> Self {
        Self(ArenaIndex::new(0, 0))
    }

    /// Creates a new ephemeral task ID outside the runtime arena.
    ///
    /// br-asupersync-u3gsst — **Test / test-internals only.** See
    /// [`RegionId::new_ephemeral`] for the rationale: production task
    /// IDs MUST come from the runtime's task arena. Gated to
    /// `cfg(any(test, feature = "test-internals"))`. The single
    /// runtime-internal bootstrap call in `app.rs` uses the
    /// `pub(crate)` [`next_bootstrap_task_id`] instead.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-internals"))]
    #[inline]
    #[must_use]
    pub fn new_ephemeral() -> Self {
        next_bootstrap_task_id()
    }
}

impl fmt::Debug for TaskId {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TaskId({}:{})", self.0.index(), self.0.generation())
    }
}

impl fmt::Display for TaskId {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "T{}", self.0.index())
    }
}

impl Serialize for TaskId {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SerdeIdEnvelope::from_arena(self.0, KIND_TASK_ID).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TaskId {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let env = SerdeIdEnvelope::deserialize(deserializer)?;
        env.check_kind::<D::Error>(KIND_TASK_ID)?;
        Ok(Self(env.to_arena()))
    }
}

/// A unique identifier for an obligation in the runtime.
///
/// Obligations represent resources that must be resolved (commit, abort, ack, etc.)
/// before their owning region can close.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObligationId(pub(crate) ArenaIndex);

impl ObligationId {
    /// Creates a new obligation ID from an arena index (internal use).
    #[inline]
    #[must_use]
    #[allow(dead_code)]
    pub(crate) const fn from_arena(index: ArenaIndex) -> Self {
        Self(index)
    }

    /// Returns a 64-bit integer representation of this `ObligationId`,
    /// suitable for hashing, sorting, and trace identity. Parity with
    /// `RegionId::as_u64` and `TaskId::as_u64`.
    #[inline]
    #[must_use]
    pub fn as_u64(&self) -> u64 {
        ((self.0.generation() as u64) << 32) | (self.0.index() as u64)
    }

    /// Returns the underlying arena index (internal use).
    #[inline]
    #[must_use]
    #[allow(dead_code)]
    #[cfg(not(feature = "test-internals"))]
    pub(crate) const fn arena_index(self) -> ArenaIndex {
        self.0
    }

    /// Returns the underlying arena index (internal use).
    #[inline]
    #[must_use]
    #[allow(dead_code)]
    #[cfg(feature = "test-internals")]
    pub const fn arena_index(self) -> ArenaIndex {
        self.0
    }

    /// Creates an obligation ID for testing/benchmarking purposes.
    ///
    /// br-asupersync-bm08jx: gated behind
    /// `cfg(any(test, feature = "test-internals"))` — same rationale
    /// as [`RegionId::new_for_test`]. Production crates that disable
    /// `test-internals` cannot forge `ObligationId`s; the runtime's
    /// obligation table is the only supported source.
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-internals"))]
    #[inline]
    #[must_use]
    pub const fn new_for_test(index: u32, generation: u32) -> Self {
        Self(ArenaIndex::new(index, generation))
    }
}

impl fmt::Debug for ObligationId {
    #[inline]
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
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "O{}", self.0.index())
    }
}

impl Serialize for ObligationId {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SerdeIdEnvelope::from_arena(self.0, KIND_OBLIGATION_ID).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ObligationId {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let env = SerdeIdEnvelope::deserialize(deserializer)?;
        env.check_kind::<D::Error>(KIND_OBLIGATION_ID)?;
        Ok(Self(env.to_arena()))
    }
}

/// A logical timestamp for the runtime.
///
/// In the production runtime, this corresponds to wall-clock time.
/// In the lab runtime, this is virtual time controlled by the scheduler.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
pub struct Time(u64);

impl Time {
    /// The zero instant (epoch).
    pub const ZERO: Self = Self(0);

    /// The maximum representable instant.
    pub const MAX: Self = Self(u64::MAX);

    /// Creates a new time from nanoseconds since epoch.
    #[inline]
    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    /// Creates a new time from milliseconds since epoch.
    #[inline]
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis.saturating_mul(1_000_000))
    }

    /// Creates a new time from seconds since epoch.
    #[inline]
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs.saturating_mul(1_000_000_000))
    }

    /// Returns the time as nanoseconds since epoch.
    #[inline]
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// Returns the time as milliseconds since epoch (truncated).
    #[inline]
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0 / 1_000_000
    }

    /// Returns the time as seconds since epoch (truncated).
    #[inline]
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0 / 1_000_000_000
    }

    /// Adds a duration in nanoseconds, saturating on overflow.
    #[inline]
    #[must_use]
    pub const fn saturating_add_nanos(self, nanos: u64) -> Self {
        Self(self.0.saturating_add(nanos))
    }

    /// Subtracts a duration in nanoseconds, saturating at zero.
    #[inline]
    #[must_use]
    pub const fn saturating_sub_nanos(self, nanos: u64) -> Self {
        Self(self.0.saturating_sub(nanos))
    }

    /// Returns the duration between two times in nanoseconds.
    ///
    /// Returns 0 if `self` is before `earlier` (time travel protection).
    /// This method uses saturating arithmetic to prevent overflow.
    #[inline]
    #[must_use]
    pub const fn duration_since(self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

impl Add<Duration> for Time {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Duration) -> Self::Output {
        let nanos: u64 = rhs.as_nanos().min(u128::from(u64::MAX)) as u64;
        self.saturating_add_nanos(nanos)
    }
}

impl fmt::Debug for Time {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Time({}ns)", self.0)
    }
}

impl fmt::Display for Time {
    #[inline]
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
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
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

    // ---- RegionId ----

    #[test]
    fn region_id_debug_format() {
        let id = RegionId::new_for_test(5, 3);
        let dbg = format!("{id:?}");
        assert!(dbg.contains("RegionId"), "{dbg}");
        assert!(dbg.contains('5'), "{dbg}");
        assert!(dbg.contains('3'), "{dbg}");
    }

    #[test]
    fn region_id_display_format() {
        let id = RegionId::new_for_test(42, 0);
        assert_eq!(format!("{id}"), "R42");
    }

    #[test]
    fn region_id_equality_and_hash() {
        use crate::util::DetHasher;
        use std::hash::{Hash, Hasher};

        let a = RegionId::new_for_test(1, 2);
        let b = RegionId::new_for_test(1, 2);
        let c = RegionId::new_for_test(1, 3);

        assert_eq!(a, b);
        assert_ne!(a, c);

        let mut ha = DetHasher::default();
        let mut hb = DetHasher::default();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn region_id_ordering() {
        let a = RegionId::new_for_test(1, 0);
        let b = RegionId::new_for_test(2, 0);
        assert!(a < b);
        assert!(a <= b);
        assert!(b > a);
    }

    #[test]
    fn region_id_copy_clone() {
        let id = RegionId::new_for_test(1, 0);
        let copied = id;
        let cloned = id;
        assert_eq!(id, copied);
        assert_eq!(id, cloned);
    }

    #[test]
    fn region_id_testing_default() {
        let id = RegionId::testing_default();
        assert_eq!(format!("{id}"), "R0");
    }

    #[test]
    fn region_id_ephemeral_unique() {
        let a = RegionId::new_ephemeral();
        let b = RegionId::new_ephemeral();
        assert_ne!(a, b);
    }

    #[test]
    fn region_id_serde_roundtrip() {
        let id = RegionId::new_for_test(99, 7);
        let json = serde_json::to_string(&id).expect("serialize");
        let deserialized: RegionId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, deserialized);
    }

    // ---- TaskId ----

    #[test]
    fn task_id_debug_format() {
        let id = TaskId::new_for_test(10, 2);
        let dbg = format!("{id:?}");
        assert!(dbg.contains("TaskId"), "{dbg}");
        assert!(dbg.contains("10"), "{dbg}");
        assert!(dbg.contains('2'), "{dbg}");
    }

    #[test]
    fn task_id_display_format() {
        let id = TaskId::new_for_test(7, 0);
        assert_eq!(format!("{id}"), "T7");
    }

    #[test]
    fn task_id_equality_and_hash() {
        use crate::util::DetHasher;
        use std::hash::{Hash, Hasher};

        let a = TaskId::new_for_test(3, 1);
        let b = TaskId::new_for_test(3, 1);
        let c = TaskId::new_for_test(3, 2);

        assert_eq!(a, b);
        assert_ne!(a, c);

        let mut ha = DetHasher::default();
        let mut hb = DetHasher::default();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn task_id_ordering() {
        let a = TaskId::new_for_test(1, 0);
        let b = TaskId::new_for_test(2, 0);
        assert!(a < b);
    }

    #[test]
    fn task_id_copy_clone() {
        let id = TaskId::new_for_test(5, 1);
        let copied = id;
        let cloned = id;
        assert_eq!(id, copied);
        assert_eq!(id, cloned);
    }

    #[test]
    fn task_id_testing_default() {
        let id = TaskId::testing_default();
        assert_eq!(format!("{id}"), "T0");
    }

    #[test]
    fn task_id_ephemeral_unique() {
        let a = TaskId::new_ephemeral();
        let b = TaskId::new_ephemeral();
        assert_ne!(a, b);
    }

    #[test]
    fn task_id_serde_roundtrip() {
        let id = TaskId::new_for_test(42, 5);
        let json = serde_json::to_string(&id).expect("serialize");
        let deserialized: TaskId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, deserialized);
    }

    // ---- ObligationId ----

    #[test]
    fn obligation_id_debug_format() {
        let id = ObligationId::new_for_test(8, 1);
        let dbg = format!("{id:?}");
        assert!(dbg.contains("ObligationId"), "{dbg}");
        assert!(dbg.contains('8'), "{dbg}");
    }

    #[test]
    fn obligation_id_display_format() {
        let id = ObligationId::new_for_test(3, 0);
        assert_eq!(format!("{id}"), "O3");
    }

    #[test]
    fn obligation_id_equality_and_hash() {
        use crate::util::DetHasher;
        use std::hash::{Hash, Hasher};

        let a = ObligationId::new_for_test(1, 1);
        let b = ObligationId::new_for_test(1, 1);
        let c = ObligationId::new_for_test(2, 1);

        assert_eq!(a, b);
        assert_ne!(a, c);

        let mut ha = DetHasher::default();
        let mut hb = DetHasher::default();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn obligation_id_ordering() {
        let a = ObligationId::new_for_test(1, 0);
        let b = ObligationId::new_for_test(2, 0);
        assert!(a < b);
    }

    #[test]
    fn obligation_id_copy_clone() {
        let id = ObligationId::new_for_test(1, 0);
        let copied = id;
        let cloned = id;
        assert_eq!(id, copied);
        assert_eq!(id, cloned);
    }

    #[test]
    fn obligation_id_serde_roundtrip() {
        let id = ObligationId::new_for_test(77, 3);
        let json = serde_json::to_string(&id).expect("serialize");
        let deserialized: ObligationId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, deserialized);
    }

    // ---- Time Display ----

    #[test]
    fn time_display_seconds() {
        let t = Time::from_secs(2);
        let disp = format!("{t}");
        assert_eq!(disp, "2.000s");
    }

    #[test]
    fn time_display_seconds_with_millis() {
        let t = Time::from_nanos(1_234_000_000);
        let disp = format!("{t}");
        assert_eq!(disp, "1.234s");
    }

    #[test]
    fn time_display_milliseconds() {
        let t = Time::from_millis(500);
        let disp = format!("{t}");
        assert_eq!(disp, "500ms");
    }

    #[test]
    fn time_display_microseconds() {
        let t = Time::from_nanos(5_000);
        let disp = format!("{t}");
        assert_eq!(disp, "5us");
    }

    #[test]
    fn time_display_nanoseconds() {
        let t = Time::from_nanos(42);
        let disp = format!("{t}");
        assert_eq!(disp, "42ns");
    }

    #[test]
    fn time_display_zero() {
        assert_eq!(format!("{}", Time::ZERO), "0ns");
    }

    // ---- Time edge cases ----

    #[test]
    fn time_debug_format() {
        let t = Time::from_nanos(100);
        let dbg = format!("{t:?}");
        assert_eq!(dbg, "Time(100ns)");
    }

    #[test]
    fn time_default_is_zero() {
        assert_eq!(Time::default(), Time::ZERO);
    }

    #[test]
    fn time_max_constant() {
        assert_eq!(Time::MAX.as_nanos(), u64::MAX);
    }

    #[test]
    fn time_saturating_add_overflow() {
        let t = Time::MAX;
        let result = t.saturating_add_nanos(1);
        assert_eq!(result, Time::MAX);
    }

    #[test]
    fn time_saturating_sub_underflow() {
        let t = Time::ZERO;
        let result = t.saturating_sub_nanos(100);
        assert_eq!(result, Time::ZERO);
    }

    #[test]
    fn time_duration_since() {
        let t1 = Time::from_secs(5);
        let t2 = Time::from_secs(3);
        assert_eq!(t1.duration_since(t2), 2_000_000_000);
        assert_eq!(t2.duration_since(t1), 0); // saturates at 0
    }

    #[test]
    fn time_add_duration() {
        let t = Time::from_secs(1);
        let result = t + Duration::from_millis(500);
        assert_eq!(result.as_millis(), 1500);
    }

    #[test]
    fn time_from_millis_saturation() {
        let t = Time::from_millis(u64::MAX);
        // Should saturate, not overflow
        assert_eq!(t, Time::MAX);
    }

    #[test]
    fn time_from_secs_saturation() {
        let t = Time::from_secs(u64::MAX);
        assert_eq!(t, Time::MAX);
    }

    #[test]
    fn time_serde_roundtrip() {
        let t = Time::from_nanos(12345);
        let json = serde_json::to_string(&t).expect("serialize");
        let deserialized: Time = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(t, deserialized);
    }

    #[test]
    fn time_hash_consistency() {
        use crate::util::DetHasher;
        use std::hash::{Hash, Hasher};

        let a = Time::from_secs(1);
        let b = Time::from_millis(1000);
        assert_eq!(a, b);

        let mut ha = DetHasher::default();
        let mut hb = DetHasher::default();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    /// br-asupersync-u3gsst — bootstrap helpers mint distinct IDs and
    /// keep generation pinned at 1 (the documented contract).
    #[test]
    fn bootstrap_helpers_mint_unique_ids() {
        let r1 = next_bootstrap_region_id();
        let r2 = next_bootstrap_region_id();
        assert_ne!(r1, r2);
        assert_eq!(r1.arena_index().generation(), 1);
        assert_eq!(r2.arena_index().generation(), 1);

        let t1 = next_bootstrap_task_id();
        let t2 = next_bootstrap_task_id();
        assert_ne!(t1, t2);
        assert_eq!(t1.arena_index().generation(), 1);
        assert_eq!(t2.arena_index().generation(), 1);
    }

    /// br-asupersync-o2oa4l — Cross-type ID confusion: a serialised
    /// RegionId must not deserialise as TaskId / ObligationId, even
    /// when their arena (index, generation) tuples are identical.
    /// The discriminant tag rejects the mis-typed payload at the
    /// envelope level.
    #[test]
    fn serde_rejects_cross_type_id_confusion() {
        let region = RegionId::from_arena(ArenaIndex::new(7, 3));
        let json = serde_json::to_string(&region).expect("serialise RegionId");
        // Sanity: the wire form contains the discriminant tag.
        assert!(json.contains("\"kind\""));
        assert!(json.contains("RegionId"));

        // Round-trip back to the original type works.
        let region_back: RegionId = serde_json::from_str(&json).expect("RegionId round-trip");
        assert_eq!(region_back, region);

        // Cross-type deserialisation must fail.
        let task_err = serde_json::from_str::<TaskId>(&json);
        assert!(task_err.is_err(), "TaskId must reject RegionId payload");
        let obl_err = serde_json::from_str::<ObligationId>(&json);
        assert!(
            obl_err.is_err(),
            "ObligationId must reject RegionId payload"
        );
    }

    /// br-asupersync-o2oa4l — TaskId / ObligationId must each reject
    /// payloads tagged for the other type.
    #[test]
    fn serde_rejects_task_obligation_confusion() {
        let task = TaskId::from_arena(ArenaIndex::new(11, 2));
        let task_json = serde_json::to_string(&task).expect("serialise TaskId");
        assert!(serde_json::from_str::<RegionId>(&task_json).is_err());
        assert!(serde_json::from_str::<ObligationId>(&task_json).is_err());
        let task_back: TaskId = serde_json::from_str(&task_json).expect("TaskId round-trip");
        assert_eq!(task_back, task);

        let obl = ObligationId::from_arena(ArenaIndex::new(11, 2));
        let obl_json = serde_json::to_string(&obl).expect("serialise ObligationId");
        assert!(serde_json::from_str::<RegionId>(&obl_json).is_err());
        assert!(serde_json::from_str::<TaskId>(&obl_json).is_err());
    }
}
