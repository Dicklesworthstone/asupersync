//! Vector clocks for causal ordering of distributed trace events.
//!
//! A vector clock maps each node in the system to a logical counter. It captures
//! the causal partial order: events are either causally ordered (happens-before)
//! or concurrent. This avoids imposing a false total order on distributed events.
//!
//! # Usage
//!
//! ```rust
//! use asupersync::trace::distributed::vclock::{VectorClock, CausalOrder};
//! use asupersync::remote::NodeId;
//!
//! let mut vc_a = VectorClock::new();
//! let node_a = NodeId::new("node-a");
//! let node_b = NodeId::new("node-b");
//!
//! vc_a.increment(&node_a);
//! vc_a.increment(&node_a);
//!
//! let mut vc_b = VectorClock::new();
//! vc_b.increment(&node_b);
//!
//! // These are concurrent — neither happened before the other.
//! assert_eq!(vc_a.partial_cmp(&vc_b), None);
//!
//! // Merge to get the join (componentwise max).
//! let merged = vc_a.merge(&vc_b);
//! assert!(merged.get(&node_a) == 2);
//! assert!(merged.get(&node_b) == 1);
//! ```

use crate::remote::NodeId;
use crate::time::{TimeSource, TimerDriverHandle, WallClock};
use crate::types::Time;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Logical clock trait for causally ordering distributed events.
///
/// Uses `PartialOrd` so vector clocks (partial order) are supported.
pub trait LogicalClock: Send + Sync {
    /// The time representation produced by this clock.
    type Time: Clone + PartialOrd + Send + Sync + 'static;

    /// Records a local event and returns the updated time.
    #[must_use]
    fn tick(&self) -> Self::Time;

    /// Updates the clock based on a received time and returns the updated time.
    #[must_use]
    fn receive(&self, sender_time: &Self::Time) -> Self::Time;

    /// Returns the current time without ticking.
    #[must_use]
    fn now(&self) -> Self::Time;
}

/// Logical time for Lamport clocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LamportTime(u64);

impl LamportTime {
    /// Returns the raw counter value.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Creates a Lamport time from a raw counter value.
    #[must_use]
    pub const fn from_raw(value: u64) -> Self {
        Self(value)
    }
}

/// Lamport logical clock (single counter).
pub struct LamportClock {
    counter: AtomicU64,
}

impl LamportClock {
    /// Creates a new Lamport clock starting at zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }

    /// Creates a Lamport clock starting at the given value.
    #[must_use]
    pub fn with_start(start: u64) -> Self {
        Self {
            counter: AtomicU64::new(start),
        }
    }

    /// Returns the current Lamport time without incrementing.
    #[must_use]
    pub fn now(&self) -> LamportTime {
        LamportTime(self.counter.load(Ordering::Acquire))
    }

    /// Records a local event and returns the updated time.
    #[must_use]
    pub fn tick(&self) -> LamportTime {
        LamportTime(self.counter.fetch_add(1, Ordering::AcqRel) + 1)
    }

    /// Merges a received Lamport time and returns the updated time.
    #[must_use]
    pub fn receive(&self, sender: LamportTime) -> LamportTime {
        let mut current = self.counter.load(Ordering::Acquire);
        loop {
            let next = current.max(sender.raw()) + 1;
            match self.counter.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return LamportTime(next),
                Err(actual) => current = actual,
            }
        }
    }
}

impl Default for LamportClock {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for LamportClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LamportClock")
            .field("counter", &self.counter.load(Ordering::Relaxed))
            .finish()
    }
}

impl LogicalClock for LamportClock {
    type Time = LamportTime;

    fn tick(&self) -> Self::Time {
        Self::tick(self)
    }

    fn receive(&self, sender_time: &Self::Time) -> Self::Time {
        Self::receive(self, *sender_time)
    }

    fn now(&self) -> Self::Time {
        Self::now(self)
    }
}

/// Logical time for hybrid clocks (physical + logical).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HybridTime {
    physical: Time,
    logical: u64,
}

impl HybridTime {
    /// Creates a new hybrid time.
    #[must_use]
    pub const fn new(physical: Time, logical: u64) -> Self {
        Self { physical, logical }
    }

    /// Returns the physical component.
    #[must_use]
    pub const fn physical(self) -> Time {
        self.physical
    }

    /// Returns the logical component.
    #[must_use]
    pub const fn logical(self) -> u64 {
        self.logical
    }
}

#[derive(Debug)]
struct HybridState {
    last_physical: Time,
    logical: u64,
}

/// Hybrid logical clock (HLC) with a monotonic physical component.
pub struct HybridClock {
    time_source: Arc<dyn TimeSource>,
    state: Mutex<HybridState>,
}

impl HybridClock {
    /// Creates a new hybrid clock using the provided time source.
    #[must_use]
    pub fn new(time_source: Arc<dyn TimeSource>) -> Self {
        let now = time_source.now();
        Self {
            time_source,
            state: Mutex::new(HybridState {
                last_physical: now,
                logical: 0,
            }),
        }
    }

    /// Returns the current hybrid time without ticking.
    #[must_use]
    pub fn now(&self) -> HybridTime {
        let state = self.state.lock();
        let physical = self.physical_now(&state);
        HybridTime::new(physical, state.logical)
    }

    /// Records a local event and returns the updated time.
    #[must_use]
    pub fn tick(&self) -> HybridTime {
        let mut state = self.state.lock();
        let physical = self.physical_now(&state);
        if physical == state.last_physical {
            state.logical = state.logical.saturating_add(1);
        } else {
            state.last_physical = physical;
            state.logical = 0;
        }
        HybridTime::new(state.last_physical, state.logical)
    }

    /// Merges a received hybrid time and returns the updated time.
    #[must_use]
    pub fn receive(&self, sender: HybridTime) -> HybridTime {
        let mut state = self.state.lock();
        let physical_now = self.physical_now(&state);
        let max_physical = physical_now.max(state.last_physical).max(sender.physical);

        let next_logical = if max_physical == state.last_physical && max_physical == sender.physical
        {
            state.logical.max(sender.logical).saturating_add(1)
        } else if max_physical == state.last_physical {
            state.logical.saturating_add(1)
        } else if max_physical == sender.physical {
            sender.logical.saturating_add(1)
        } else {
            0
        };

        state.last_physical = max_physical;
        state.logical = next_logical;
        HybridTime::new(state.last_physical, state.logical)
    }

    fn physical_now(&self, state: &HybridState) -> Time {
        let physical = self.time_source.now();
        if physical < state.last_physical {
            state.last_physical
        } else {
            physical
        }
    }
}

impl fmt::Debug for HybridClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock();
        f.debug_struct("HybridClock")
            .field("last_physical", &state.last_physical)
            .field("logical", &state.logical)
            .finish_non_exhaustive()
    }
}

impl LogicalClock for HybridClock {
    type Time = HybridTime;

    fn tick(&self) -> Self::Time {
        Self::tick(self)
    }

    fn receive(&self, sender_time: &Self::Time) -> Self::Time {
        Self::receive(self, *sender_time)
    }

    fn now(&self) -> Self::Time {
        Self::now(self)
    }
}

/// Logical clock wrapper for vector clocks with a local node identity.
pub struct VectorClockHandle {
    /// Local node identity for this vector clock.
    node: NodeId,
    /// Internal vector clock state protected by a mutex.
    clock: Mutex<VectorClock>,
}

impl VectorClockHandle {
    /// Creates a new vector clock handle for the given node.
    #[must_use]
    pub fn new(node: NodeId) -> Self {
        Self {
            node,
            clock: Mutex::new(VectorClock::new()),
        }
    }

    /// Returns the current vector clock snapshot.
    #[must_use]
    pub fn current(&self) -> VectorClock {
        self.clock.lock().clone()
    }
}

impl fmt::Debug for VectorClockHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VectorClockHandle")
            .field("node", &self.node)
            .field("clock", &self.clock.lock())
            .finish()
    }
}

impl LogicalClock for VectorClockHandle {
    type Time = VectorClock;

    fn tick(&self) -> Self::Time {
        let mut clock = self.clock.lock();
        clock.increment(&self.node);
        clock.clone()
    }

    fn receive(&self, sender_time: &Self::Time) -> Self::Time {
        let mut clock = self.clock.lock();
        clock.receive(&self.node, sender_time);
        clock.clone()
    }

    fn now(&self) -> Self::Time {
        self.clock.lock().clone()
    }
}

/// Logical time values for heterogeneous clock types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogicalTime {
    /// Lamport clock time.
    Lamport(LamportTime),
    /// Vector clock time.
    Vector(VectorClock),
    /// Hybrid clock time.
    Hybrid(HybridTime),
}

impl LogicalTime {
    /// Returns the logical clock kind for this time value.
    #[must_use]
    pub const fn kind(&self) -> LogicalClockKind {
        match self {
            Self::Lamport(_) => LogicalClockKind::Lamport,
            Self::Vector(_) => LogicalClockKind::Vector,
            Self::Hybrid(_) => LogicalClockKind::Hybrid,
        }
    }

    /// Compares two logical times for causal ordering.
    ///
    /// Returns the causal relationship between `self` and `other`.
    /// For Lamport/Hybrid clocks this is derived from total/partial order;
    /// for vector clocks this uses the vector clock causal order directly.
    ///
    /// Returns `CausalOrder::Concurrent` if the clock types differ.
    #[must_use]
    pub fn causal_order(&self, other: &Self) -> CausalOrder {
        match (self, other) {
            (Self::Vector(a), Self::Vector(b)) => a.causal_order(b),
            _ => match self.partial_cmp(other) {
                Some(std::cmp::Ordering::Less) => CausalOrder::Before,
                Some(std::cmp::Ordering::Greater) => CausalOrder::After,
                Some(std::cmp::Ordering::Equal) => CausalOrder::Equal,
                None => CausalOrder::Concurrent,
            },
        }
    }
}

impl PartialOrd for LogicalTime {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match (self, other) {
            (Self::Lamport(a), Self::Lamport(b)) => a.partial_cmp(b),
            (Self::Vector(a), Self::Vector(b)) => a.partial_cmp(b),
            (Self::Hybrid(a), Self::Hybrid(b)) => a.partial_cmp(b),
            _ => None,
        }
    }
}

/// Kind of logical clock in use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogicalClockKind {
    /// Lamport clock.
    Lamport,
    /// Vector clock.
    Vector,
    /// Hybrid clock.
    Hybrid,
}

/// Runtime-selected logical clock configuration.
#[derive(Clone, Debug)]
pub enum LogicalClockMode {
    /// Use a Lamport clock.
    Lamport,
    /// Use a vector clock with the provided local node id.
    Vector {
        /// Local node identity for vector clock tracking.
        node: NodeId,
    },
    /// Use a hybrid logical clock.
    Hybrid,
}

/// Opaque handle to a logical clock instance.
#[derive(Clone)]
pub enum LogicalClockHandle {
    /// Lamport clock handle.
    Lamport(Arc<LamportClock>),
    /// Vector clock handle.
    Vector(Arc<VectorClockHandle>),
    /// Hybrid clock handle.
    Hybrid(Arc<HybridClock>),
}

impl LogicalClockHandle {
    /// Returns the kind of clock this handle wraps.
    #[must_use]
    pub const fn kind(&self) -> LogicalClockKind {
        match self {
            Self::Lamport(_) => LogicalClockKind::Lamport,
            Self::Vector(_) => LogicalClockKind::Vector,
            Self::Hybrid(_) => LogicalClockKind::Hybrid,
        }
    }

    /// Records a local event and returns the updated logical time.
    #[must_use]
    pub fn tick(&self) -> LogicalTime {
        match self {
            Self::Lamport(clock) => LogicalTime::Lamport(clock.tick()),
            Self::Vector(clock) => LogicalTime::Vector(clock.tick()),
            Self::Hybrid(clock) => LogicalTime::Hybrid(clock.tick()),
        }
    }

    /// Updates the clock using a received logical time and returns the updated time.
    #[must_use]
    pub fn receive(&self, sender_time: &LogicalTime) -> LogicalTime {
        match (self, sender_time) {
            (Self::Lamport(clock), LogicalTime::Lamport(time)) => {
                LogicalTime::Lamport(clock.receive(*time))
            }
            (Self::Vector(clock), LogicalTime::Vector(time)) => {
                LogicalTime::Vector(clock.receive(time))
            }
            (Self::Hybrid(clock), LogicalTime::Hybrid(time)) => {
                LogicalTime::Hybrid(clock.receive(*time))
            }
            // Mismatched clock kinds: fall back to a local tick.
            _ => self.tick(),
        }
    }

    /// Returns the current logical time without ticking.
    #[must_use]
    pub fn now(&self) -> LogicalTime {
        match self {
            Self::Lamport(clock) => LogicalTime::Lamport(clock.now()),
            Self::Vector(clock) => LogicalTime::Vector(clock.now()),
            Self::Hybrid(clock) => LogicalTime::Hybrid(clock.now()),
        }
    }
}

impl fmt::Debug for LogicalClockHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lamport(_) => f.write_str("LogicalClockHandle::Lamport"),
            Self::Vector(_) => f.write_str("LogicalClockHandle::Vector"),
            Self::Hybrid(_) => f.write_str("LogicalClockHandle::Hybrid"),
        }
    }
}

impl Default for LogicalClockHandle {
    fn default() -> Self {
        Self::Lamport(Arc::new(LamportClock::new()))
    }
}

impl LogicalClockMode {
    /// Builds a logical clock handle for the given timer driver context.
    #[must_use]
    pub fn build_handle(&self, timer_driver: Option<TimerDriverHandle>) -> LogicalClockHandle {
        match self {
            Self::Lamport => LogicalClockHandle::Lamport(Arc::new(LamportClock::new())),
            Self::Vector { node } => {
                LogicalClockHandle::Vector(Arc::new(VectorClockHandle::new(node.clone())))
            }
            Self::Hybrid => {
                let time_source: Arc<dyn TimeSource> = match timer_driver {
                    Some(driver) => Arc::new(TimerDriverSource::new(driver)),
                    None => Arc::new(WallClock::new()),
                };
                LogicalClockHandle::Hybrid(Arc::new(HybridClock::new(time_source)))
            }
        }
    }
}

#[derive(Clone)]
struct TimerDriverSource {
    timer: TimerDriverHandle,
}

impl TimerDriverSource {
    fn new(timer: TimerDriverHandle) -> Self {
        Self { timer }
    }
}

impl fmt::Debug for TimerDriverSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimerDriverSource").finish()
    }
}

impl TimeSource for TimerDriverSource {
    fn now(&self) -> Time {
        self.timer.now()
    }
}

/// A vector clock for causal ordering in a distributed system.
///
/// Maps `NodeId → u64` counters. The partial order is:
/// - `a ≤ b` iff `∀ node: a[node] ≤ b[node]`
/// - `a < b` (happens-before) iff `a ≤ b` and `a ≠ b`
/// - `a ∥ b` (concurrent) iff `¬(a ≤ b)` and `¬(b ≤ a)`
#[derive(Clone, PartialEq, Eq)]
pub struct VectorClock {
    /// BTreeMap for deterministic iteration order.
    entries: BTreeMap<NodeId, u64>,
}

impl VectorClock {
    /// Creates an empty vector clock (all components zero).
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Creates a vector clock with a single node initialized to 1.
    #[must_use]
    pub fn for_node(node: &NodeId) -> Self {
        let mut vc = Self::new();
        vc.entries.insert(node.clone(), 1);
        vc
    }

    /// Returns the counter for the given node (0 if absent).
    #[must_use]
    pub fn get(&self, node: &NodeId) -> u64 {
        self.entries.get(node).copied().unwrap_or(0)
    }

    /// Increments the counter for the given node and returns the new value.
    pub fn increment(&mut self, node: &NodeId) -> u64 {
        let entry = self.entries.entry(node.clone()).or_insert(0);
        *entry += 1;
        *entry
    }

    /// Sets the counter for a node to a specific value, monotone.
    ///
    /// Used when receiving a message: update local clock to be at least
    /// as large as the sender's value for each node.
    pub fn set(&mut self, node: &NodeId, value: u64) {
        if value == 0 {
            return;
        }
        let entry = self.entries.entry(node.clone()).or_insert(0);
        if value > *entry {
            *entry = value;
        }
    }

    /// Returns the merge (join / componentwise max) of two vector clocks.
    ///
    /// This is the least upper bound in the partial order.
    #[must_use]
    pub fn merge(&self, other: &Self) -> Self {
        let mut result = self.clone();
        for (node, &value) in &other.entries {
            let entry = result.entries.entry(node.clone()).or_insert(0);
            if value > *entry {
                *entry = value;
            }
        }
        result
    }

    /// Merges another vector clock into `self` in place.
    pub fn merge_in(&mut self, other: &Self) {
        for (node, &value) in &other.entries {
            let entry = self.entries.entry(node.clone()).or_insert(0);
            if value > *entry {
                *entry = value;
            }
        }
    }

    /// Increments the local node and merges the remote clock.
    ///
    /// This is the standard "on receive" operation:
    /// 1. Merge the incoming clock
    /// 2. Increment the local counter
    pub fn receive(&mut self, local_node: &NodeId, remote_clock: &Self) {
        self.merge_in(remote_clock);
        self.increment(local_node);
    }

    /// Compares two vector clocks for causal ordering.
    #[must_use]
    pub fn causal_order(&self, other: &Self) -> CausalOrder {
        let mut self_leq_other = true;
        let mut other_leq_self = true;

        // Check all nodes present in either clock.
        let all_nodes: std::collections::BTreeSet<&NodeId> =
            self.entries.keys().chain(other.entries.keys()).collect();

        for node in all_nodes {
            let a = self.get(node);
            let b = other.get(node);
            if a > b {
                self_leq_other = false;
            }
            if b > a {
                other_leq_self = false;
            }
            if !self_leq_other && !other_leq_self {
                return CausalOrder::Concurrent;
            }
        }

        match (self_leq_other, other_leq_self) {
            (true, true) => CausalOrder::Equal,
            (true, false) => CausalOrder::Before,
            (false, true) => CausalOrder::After,
            (false, false) => CausalOrder::Concurrent,
        }
    }

    /// Returns true if `self` happens-before `other`.
    #[must_use]
    pub fn happens_before(&self, other: &Self) -> bool {
        self.causal_order(other) == CausalOrder::Before
    }

    /// Returns true if `self` and `other` are concurrent.
    #[must_use]
    pub fn is_concurrent_with(&self, other: &Self) -> bool {
        self.causal_order(other) == CausalOrder::Concurrent
    }

    /// Returns the number of nodes tracked by this clock.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if all counters are zero (empty clock).
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns an iterator over (node, counter) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&NodeId, &u64)> {
        self.entries.iter()
    }
}

impl Default for VectorClock {
    fn default() -> Self {
        Self::new()
    }
}

/// Implements the partial order for vector clocks.
///
/// Returns `None` when the clocks are concurrent (incomparable).
impl PartialOrd for VectorClock {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match self.causal_order(other) {
            CausalOrder::Before => Some(std::cmp::Ordering::Less),
            CausalOrder::After => Some(std::cmp::Ordering::Greater),
            CausalOrder::Equal => Some(std::cmp::Ordering::Equal),
            CausalOrder::Concurrent => None,
        }
    }
}

impl fmt::Debug for VectorClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VC{{")?;
        for (i, (node, value)) in self.entries.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}:{}", node.as_str(), value)?;
        }
        write!(f, "}}")
    }
}

impl fmt::Display for VectorClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;
        for (i, (node, value)) in self.entries.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}={}", node.as_str(), value)?;
        }
        write!(f, "]")
    }
}

/// Result of comparing two vector clocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CausalOrder {
    /// `self` happened strictly before `other`.
    Before,
    /// `self` happened strictly after `other`.
    After,
    /// `self` and `other` are exactly equal.
    Equal,
    /// `self` and `other` are concurrent (neither happened before the other).
    Concurrent,
}

/// A trace event annotated with causal metadata.
///
/// Wraps any event with the vector clock at the time the event was recorded,
/// plus the originating node.
#[derive(Clone, Debug)]
pub struct CausalEvent<T> {
    /// The originating node.
    pub origin: NodeId,
    /// The vector clock at event creation time.
    pub clock: VectorClock,
    /// The wrapped event.
    pub event: T,
}

impl<T> CausalEvent<T> {
    /// Creates a new causal event.
    pub fn new(origin: NodeId, clock: VectorClock, event: T) -> Self {
        Self {
            origin,
            clock,
            event,
        }
    }

    /// Returns true if this event causally precedes `other`.
    pub fn happens_before<U>(&self, other: &CausalEvent<U>) -> bool {
        self.clock.happens_before(&other.clock)
    }

    /// Returns true if this event is concurrent with `other`.
    pub fn is_concurrent_with<U>(&self, other: &CausalEvent<U>) -> bool {
        self.clock.is_concurrent_with(&other.clock)
    }
}

/// A causal history tracker for a single node.
///
/// Manages the local vector clock, incrementing on local events and
/// merging on message receive.
#[derive(Clone, Debug)]
pub struct CausalTracker {
    /// The local node.
    node: NodeId,
    /// The current vector clock.
    clock: VectorClock,
}

impl CausalTracker {
    /// Creates a new tracker for the given node.
    #[must_use]
    pub fn new(node: NodeId) -> Self {
        Self {
            node,
            clock: VectorClock::new(),
        }
    }

    /// Records a local event, incrementing the local counter.
    ///
    /// Returns the vector clock at the time of the event.
    pub fn record_local_event(&mut self) -> VectorClock {
        self.clock.increment(&self.node);
        self.clock.clone()
    }

    /// Records a local event, wrapping it with causal metadata.
    pub fn record<T>(&mut self, event: T) -> CausalEvent<T> {
        let clock = self.record_local_event();
        CausalEvent::new(self.node.clone(), clock, event)
    }

    /// Records a message send. Increments the local clock and returns
    /// the clock to attach to the outgoing message.
    pub fn on_send(&mut self) -> VectorClock {
        self.record_local_event()
    }

    /// Records a message receive. Merges the incoming clock and
    /// increments the local counter.
    pub fn on_receive(&mut self, remote_clock: &VectorClock) {
        self.clock.receive(&self.node, remote_clock);
    }

    /// Returns the current vector clock (snapshot).
    #[must_use]
    pub fn current_clock(&self) -> &VectorClock {
        &self.clock
    }

    /// Returns the local node ID.
    #[must_use]
    pub fn node(&self) -> &NodeId {
        &self.node
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::VirtualClock;
    use std::sync::Arc;

    fn node(name: &str) -> NodeId {
        NodeId::new(name)
    }

    #[test]
    fn empty_clocks_are_equal() {
        let a = VectorClock::new();
        let b = VectorClock::new();
        assert_eq!(a.causal_order(&b), CausalOrder::Equal);
        assert_eq!(a.partial_cmp(&b), Some(std::cmp::Ordering::Equal));
    }

    #[test]
    fn increment_creates_happens_before() {
        let n = node("A");
        let mut a = VectorClock::new();
        let b = a.clone();
        a.increment(&n);
        assert_eq!(b.causal_order(&a), CausalOrder::Before);
        assert!(b.happens_before(&a));
    }

    #[test]
    fn concurrent_detection() {
        let na = node("A");
        let nb = node("B");
        let mut a = VectorClock::new();
        let mut b = VectorClock::new();
        a.increment(&na);
        b.increment(&nb);
        assert_eq!(a.causal_order(&b), CausalOrder::Concurrent);
        assert!(a.is_concurrent_with(&b));
        assert_eq!(a.partial_cmp(&b), None);
    }

    #[test]
    fn lamport_tick_and_receive() {
        let clock = LamportClock::new();
        let t1 = clock.tick();
        let t2 = clock.tick();
        assert!(t2 > t1);

        let remote = LamportTime::from_raw(10);
        let merged = clock.receive(remote);
        assert!(merged.raw() > remote.raw());
    }

    #[test]
    fn hybrid_clock_deterministic_with_virtual_time() {
        let virtual_clock = Arc::new(VirtualClock::new());
        let hlc = HybridClock::new(virtual_clock.clone());

        let t1 = hlc.tick();
        let t2 = hlc.tick();
        assert!(t2 >= t1);

        virtual_clock.advance(1_000);
        let t3 = hlc.tick();
        assert!(t3.physical() >= t2.physical());
    }

    #[test]
    fn merge_is_least_upper_bound() {
        let na = node("A");
        let nb = node("B");
        let mut a = VectorClock::new();
        a.increment(&na);
        a.increment(&na);
        let mut b = VectorClock::new();
        b.increment(&nb);
        b.increment(&nb);
        b.increment(&nb);

        let merged = a.merge(&b);
        assert_eq!(merged.get(&na), 2);
        assert_eq!(merged.get(&nb), 3);
        // Both original clocks happen-before the merge
        assert!(a.happens_before(&merged));
        assert!(b.happens_before(&merged));
    }

    #[test]
    fn merge_is_commutative() {
        let na = node("A");
        let nb = node("B");
        let mut a = VectorClock::new();
        a.increment(&na);
        let mut b = VectorClock::new();
        b.increment(&nb);

        assert_eq!(a.merge(&b), b.merge(&a));
    }

    #[test]
    fn merge_is_associative() {
        let na = node("A");
        let nb = node("B");
        let nc = node("C");
        let mut a = VectorClock::new();
        a.increment(&na);
        let mut b = VectorClock::new();
        b.increment(&nb);
        let mut c = VectorClock::new();
        c.increment(&nc);

        let ab_c = a.merge(&b).merge(&c);
        let a_bc = a.merge(&b.merge(&c));
        assert_eq!(ab_c, a_bc);
    }

    #[test]
    fn merge_is_idempotent() {
        let na = node("A");
        let mut a = VectorClock::new();
        a.increment(&na);
        assert_eq!(a.merge(&a), a);
    }

    #[test]
    fn receive_merges_and_increments() {
        let na = node("A");
        let nb = node("B");
        let mut a = VectorClock::new();
        a.increment(&na); // A: {A:1}

        let mut b = VectorClock::new();
        b.increment(&nb); // B: {B:1}
        b.increment(&nb); // B: {B:2}

        // A receives a message with B's clock
        a.receive(&na, &b); // merge → {A:1, B:2}, then increment → {A:2, B:2}
        assert_eq!(a.get(&na), 2);
        assert_eq!(a.get(&nb), 2);
    }

    #[test]
    fn for_node_initializes_to_one() {
        let n = node("X");
        let vc = VectorClock::for_node(&n);
        assert_eq!(vc.get(&n), 1);
        assert_eq!(vc.node_count(), 1);
    }

    #[test]
    fn set_is_monotone() {
        let n = node("A");
        let mut vc = VectorClock::new();
        vc.set(&n, 3);
        assert_eq!(vc.get(&n), 3);

        // Lower value should not regress the clock.
        vc.set(&n, 1);
        assert_eq!(vc.get(&n), 3);

        // Higher value should advance.
        vc.set(&n, 7);
        assert_eq!(vc.get(&n), 7);
    }

    #[test]
    fn causal_tracker_send_receive_protocol() {
        let na = node("A");
        let nb = node("B");
        let mut tracker_a = CausalTracker::new(na.clone());
        let mut tracker_b = CausalTracker::new(nb.clone());

        // A does local work
        tracker_a.record_local_event(); // A: {A:1}

        // A sends message to B
        let msg_clock = tracker_a.on_send(); // A: {A:2}
        assert_eq!(msg_clock.get(&na), 2);

        // B receives message from A
        tracker_b.on_receive(&msg_clock); // B: merge({}, {A:2}) → {A:2}, incr → {A:2, B:1}
        assert_eq!(tracker_b.current_clock().get(&na), 2);
        assert_eq!(tracker_b.current_clock().get(&nb), 1);

        // B does more work
        tracker_b.record_local_event(); // B: {A:2, B:2}

        // B's events happen after A's send
        assert!(msg_clock.happens_before(tracker_b.current_clock()));
    }

    #[test]
    fn causal_event_ordering() {
        let na = node("A");
        let nb = node("B");
        let mut tracker_a = CausalTracker::new(na);
        let mut tracker_b = CausalTracker::new(nb);

        let e1 = tracker_a.record("event-1");
        let e2 = tracker_b.record("event-2");

        // Independent events are concurrent
        assert!(e1.is_concurrent_with(&e2));
        assert!(!e1.happens_before(&e2));
    }

    #[test]
    fn display_formatting() {
        let na = node("A");
        let nb = node("B");
        let mut vc = VectorClock::new();
        vc.increment(&na);
        vc.increment(&nb);
        vc.increment(&nb);
        let display = format!("{vc}");
        assert!(display.contains("A=1"));
        assert!(display.contains("B=2"));
    }

    #[test]
    fn partial_order_after() {
        let na = node("A");
        let mut a = VectorClock::new();
        a.increment(&na);
        let b = VectorClock::new();
        assert_eq!(a.causal_order(&b), CausalOrder::After);
        assert_eq!(a.partial_cmp(&b), Some(std::cmp::Ordering::Greater));
    }

    #[test]
    fn three_node_diamond() {
        // Classic diamond:
        //   A sends to B and C independently
        //   B and C are concurrent
        //   D receives from both B and C
        let na = node("A");
        let nb = node("B");
        let nc = node("C");
        let nd = node("D");

        let mut ta = CausalTracker::new(na);
        let mut tb = CausalTracker::new(nb);
        let mut tc = CausalTracker::new(nc);
        let mut td = CausalTracker::new(nd);

        // A sends to B and C
        let msg_to_b = ta.on_send();
        let msg_to_c = ta.on_send();

        tb.on_receive(&msg_to_b);
        tc.on_receive(&msg_to_c);

        // B and C do independent work
        let b_clock = tb.on_send();
        let c_clock = tc.on_send();

        // B and C are concurrent
        assert!(b_clock.is_concurrent_with(&c_clock));

        // D receives from B then C
        td.on_receive(&b_clock);
        td.on_receive(&c_clock);

        // D happens after both B and C
        assert!(b_clock.happens_before(td.current_clock()));
        assert!(c_clock.happens_before(td.current_clock()));
    }
}
