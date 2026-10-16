//! Trace event filtering during recording.
//!
//! This module provides [`TraceFilter`] for controlling which events are recorded
//! during trace capture. Filtering reduces trace size for targeted debugging.
//!
//! # Features
//!
//! - **Kind filtering**: Include or exclude specific event categories
//! - **Entity filtering**: Record events only for specific regions or tasks
//! - **Sampling**: Probabilistic recording for high-frequency events
//! - **Custom predicates**: User-defined filter logic
//!
//! # Example
//!
//! ```
//! use asupersync::trace::filter::{TraceFilter, EventCategory};
//!
//! // Create a filter for scheduling and time events only
//! let filter = TraceFilter::default()
//!     .include_kinds([EventCategory::Scheduling, EventCategory::Time])
//!     .with_sample_rate(0.1); // Sample 10% of high-frequency events
//!
//! // Create a minimal scheduling-only filter
//! let minimal = TraceFilter::scheduling_only();
//!
//! // Filter excluding RNG values
//! let no_rng = TraceFilter::no_rng();
//! ```

use crate::types::{RegionId, TaskId};
use std::collections::BTreeSet;
use std::sync::Arc;

type FilterPredicate = dyn Fn(&dyn FilterableEvent) -> bool + Send + Sync;

// =============================================================================
// Event Kind Categories
// =============================================================================

/// Categories of trace events for filtering.
///
/// These categories group related events for easier filtering configuration.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub enum EventCategory {
    /// Task scheduling events (scheduled, yielded, completed, spawned).
    Scheduling,

    /// Virtual time events (advanced, timers created/fired/cancelled).
    Time,

    /// I/O events (ready, result, error).
    Io,

    /// Random number generation events (seed, values).
    Rng,

    /// Region lifecycle events.
    Region,

    /// Waker invocation events.
    Waker,

    /// Chaos injection events.
    Chaos,

    /// Checkpoint events.
    Checkpoint,
}

impl EventCategory {
    /// Returns all event kinds.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Scheduling,
            Self::Time,
            Self::Io,
            Self::Rng,
            Self::Region,
            Self::Waker,
            Self::Chaos,
            Self::Checkpoint,
        ]
    }

    /// Returns event kinds that are typically high-frequency and may benefit from sampling.
    #[must_use]
    pub const fn high_frequency() -> &'static [Self] {
        &[Self::Rng, Self::Waker]
    }

    /// Returns true if this event kind is subject to sampling.
    #[must_use]
    pub fn is_sampled(&self) -> bool {
        matches!(self, Self::Rng | Self::Waker)
    }
}

// =============================================================================
// Filter Match Trait
// =============================================================================

/// Trait for extracting filter-relevant information from events.
pub trait FilterableEvent {
    /// Returns the event kind category.
    fn event_kind(&self) -> EventCategory;

    /// Returns the task ID if this event is task-scoped.
    fn task_id(&self) -> Option<TaskId>;

    /// Returns the region ID if this event is region-scoped.
    fn region_id(&self) -> Option<RegionId>;
}

// =============================================================================
// Trace Filter
// =============================================================================

/// Filter for controlling which trace events are recorded.
///
/// The filter is evaluated for each event during recording. Events that don't
/// pass the filter are dropped and not stored in the trace.
///
/// # Evaluation Order
///
/// Filters are evaluated in this order:
/// 1. Kind exclusion (if excluded, drop immediately)
/// 2. Kind inclusion (if include list is non-empty and kind not in it, drop)
/// 3. Entity filtering (region/task filters)
/// 4. Sampling (for high-frequency events)
/// 5. Custom predicate (if provided)
///
/// # Default Behavior
///
/// The default filter records all events (no filtering applied).
#[derive(Clone)]
pub struct TraceFilter {
    /// Event kinds to include (empty = all kinds).
    include_kinds: BTreeSet<EventCategory>,

    /// Event kinds to exclude (takes precedence over include).
    exclude_kinds: BTreeSet<EventCategory>,

    /// Only record events for these regions (None = all regions).
    region_filter: Option<BTreeSet<RegionId>>,

    /// Explicitly excluded regions (always dropped).
    exclude_regions: BTreeSet<RegionId>,

    /// Only record events for these tasks (None = all tasks).
    task_filter: Option<BTreeSet<TaskId>>,

    /// Sample rate for high-frequency events (0.0-1.0).
    /// 1.0 = record all, 0.5 = record 50%, 0.0 = record none.
    sample_rate: f64,

    /// Custom filter predicate (must be Send + Sync for multi-threaded use).
    /// The predicate returns true if the event should be recorded.
    custom: Option<Arc<FilterPredicate>>,

    /// RNG state for sampling decisions.
    sample_state: u64,
}

impl Default for TraceFilter {
    fn default() -> Self {
        Self {
            include_kinds: BTreeSet::new(),
            exclude_kinds: BTreeSet::new(),
            region_filter: None,
            exclude_regions: BTreeSet::new(),
            task_filter: None,
            sample_rate: 1.0,
            custom: None,
            sample_state: 0,
        }
    }
}

impl std::fmt::Debug for TraceFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraceFilter")
            .field("include_kinds", &self.include_kinds)
            .field("exclude_kinds", &self.exclude_kinds)
            .field("region_filter", &self.region_filter)
            .field("exclude_regions", &self.exclude_regions)
            .field("task_filter", &self.task_filter)
            .field("sample_rate", &self.sample_rate)
            .field("custom", &self.custom.as_ref().map(|_| "<predicate>"))
            .finish_non_exhaustive()
    }
}

impl TraceFilter {
    /// Creates a new filter that records all events.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // =========================================================================
    // Predefined Filters
    // =========================================================================

    /// Creates a filter that only records scheduling decisions.
    ///
    /// This is the minimal filter for replay that captures:
    /// - Task scheduling, yielding, and completion
    /// - RNG seed (but not values)
    /// - Chaos injections
    #[must_use]
    pub fn scheduling_only() -> Self {
        let mut filter = Self::new();
        filter.include_kinds = [EventCategory::Scheduling, EventCategory::Chaos]
            .into_iter()
            .collect();
        filter
    }

    /// Creates a filter that records everything except RNG values.
    ///
    /// This is a common configuration that:
    /// - Records all scheduling, time, I/O, and chaos events
    /// - Records RNG seed but excludes individual RNG values
    /// - Significantly reduces trace size for executions with heavy RNG use
    #[must_use]
    pub fn no_rng() -> Self {
        let mut filter = Self::new();
        filter.exclude_kinds.insert(EventCategory::Rng);
        filter
    }

    /// Creates a filter that records only events for a specific region subtree.
    ///
    /// Use this when debugging a specific region and its children.
    #[must_use]
    pub fn region_subtree(root: RegionId) -> Self {
        let mut filter = Self::new();
        let mut regions = BTreeSet::new();
        regions.insert(root);
        filter.region_filter = Some(regions);
        filter
    }

    /// Creates a filter focused on I/O events for debugging I/O-related issues.
    #[must_use]
    pub fn io_focused() -> Self {
        let mut filter = Self::new();
        filter.include_kinds = [
            EventCategory::Io,
            EventCategory::Scheduling,
            EventCategory::Time,
        ]
        .into_iter()
        .collect();
        filter
    }

    /// Creates a filter that samples high-frequency events at the given rate.
    #[must_use]
    pub fn with_sampling(rate: f64) -> Self {
        let mut filter = Self::new();
        filter.sample_rate = rate.clamp(0.0, 1.0);
        filter
    }

    // =========================================================================
    // Builder Methods
    // =========================================================================

    /// Sets the event kinds to include.
    ///
    /// If non-empty, only events of these kinds will be recorded.
    /// Kind exclusion still takes precedence.
    #[must_use]
    pub fn include_kinds<I>(mut self, kinds: I) -> Self
    where
        I: IntoIterator<Item = EventCategory>,
    {
        self.include_kinds = kinds.into_iter().collect();
        self
    }

    /// Adds an event kind to the include list.
    #[must_use]
    pub fn include_kind(mut self, kind: EventCategory) -> Self {
        self.include_kinds.insert(kind);
        self
    }

    /// Sets the event kinds to exclude.
    ///
    /// Events of these kinds will never be recorded, even if in the include list.
    #[must_use]
    pub fn exclude_kinds<I>(mut self, kinds: I) -> Self
    where
        I: IntoIterator<Item = EventCategory>,
    {
        self.exclude_kinds = kinds.into_iter().collect();
        self
    }

    /// Adds an event kind to the exclude list.
    #[must_use]
    pub fn exclude_kind(mut self, kind: EventCategory) -> Self {
        self.exclude_kinds.insert(kind);
        self
    }

    /// Sets the region filter.
    ///
    /// Only events associated with these regions will be recorded.
    /// Events not associated with any region are always recorded.
    #[must_use]
    pub fn filter_regions<I>(mut self, regions: I) -> Self
    where
        I: IntoIterator<Item = RegionId>,
    {
        self.region_filter = Some(regions.into_iter().collect());
        self
    }

    /// Adds a region to the region filter.
    #[must_use]
    pub fn include_region(mut self, region: RegionId) -> Self {
        self.region_filter
            .get_or_insert_with(BTreeSet::new)
            .insert(region);
        self
    }

    /// Excludes a specific region from recording.
    ///
    /// This is an explicit exclusion and always takes precedence over
    /// inclusion filters.
    #[must_use]
    pub fn exclude_region(mut self, region: RegionId) -> Self {
        self.exclude_regions.insert(region);
        if let Some(ref mut regions) = self.region_filter {
            regions.remove(&region);
        }
        self
    }

    /// Excludes a specific region from recording.
    ///
    /// Alias for [`exclude_region`](Self::exclude_region).
    #[must_use]
    pub fn exclude_region_explicit(self, region: RegionId) -> Self {
        self.exclude_region(region)
    }

    /// Sets the task filter.
    ///
    /// Only events associated with these tasks will be recorded.
    /// Events not associated with any task are always recorded.
    #[must_use]
    pub fn filter_tasks<I>(mut self, tasks: I) -> Self
    where
        I: IntoIterator<Item = TaskId>,
    {
        self.task_filter = Some(tasks.into_iter().collect());
        self
    }

    /// Adds a task to the task filter.
    #[must_use]
    pub fn include_task(mut self, task: TaskId) -> Self {
        self.task_filter
            .get_or_insert_with(BTreeSet::new)
            .insert(task);
        self
    }

    /// Sets the sample rate for high-frequency events.
    ///
    /// - 1.0 = record all events (no sampling)
    /// - 0.5 = record approximately 50% of sampled events
    /// - 0.0 = record no sampled events
    ///
    /// Only events in [`EventCategory::high_frequency()`] are subject to sampling.
    #[must_use]
    pub fn with_sample_rate(mut self, rate: f64) -> Self {
        self.sample_rate = rate.clamp(0.0, 1.0);
        self
    }

    /// Sets a custom filter predicate.
    ///
    /// The predicate receives each event and returns `true` if it should be recorded.
    /// This is evaluated after all other filters.
    #[must_use]
    pub fn with_custom<F>(mut self, predicate: F) -> Self
    where
        F: Fn(&dyn FilterableEvent) -> bool + Send + Sync + 'static,
    {
        self.custom = Some(Arc::new(predicate));
        self
    }

    /// Seeds the sampling RNG for reproducible filtering.
    ///
    /// This is useful for deterministic replay of filtered traces.
    #[must_use]
    pub fn with_sample_seed(mut self, seed: u64) -> Self {
        self.sample_state = seed;
        self
    }

    // =========================================================================
    // Filter Evaluation
    // =========================================================================

    /// Evaluates whether an event should be recorded.
    ///
    /// Returns `true` if the event passes all filter criteria.
    pub fn should_record(&mut self, event: &dyn FilterableEvent) -> bool {
        let kind = event.event_kind();

        // 1. Check exclusion (takes precedence)
        if self.exclude_kinds.contains(&kind) {
            return false;
        }

        // 2. Check inclusion (if include list is non-empty)
        if !self.include_kinds.is_empty() && !self.include_kinds.contains(&kind) {
            return false;
        }

        // 3. Check explicit region exclusions
        if let Some(region) = event.region_id() {
            if self.exclude_regions.contains(&region) {
                return false;
            }
        }

        // 4. Check region filter
        if let Some(ref regions) = self.region_filter {
            if let Some(region) = event.region_id() {
                if !regions.contains(&region) {
                    return false;
                }
            }
            // Events without region association pass through
        }

        // 5. Check task filter
        if let Some(ref tasks) = self.task_filter {
            if let Some(task) = event.task_id() {
                if !tasks.contains(&task) {
                    return false;
                }
            }
            // Events without task association pass through
        }

        // 6. Apply sampling for high-frequency events
        if kind.is_sampled() && self.sample_rate < 1.0 && !self.sample() {
            return false;
        }

        // 7. Apply custom predicate
        if let Some(ref predicate) = self.custom {
            if !predicate(event) {
                return false;
            }
        }

        true
    }

    /// Returns true if no filtering is configured (record all events).
    #[must_use]
    pub fn is_pass_through(&self) -> bool {
        self.include_kinds.is_empty()
            && self.exclude_kinds.is_empty()
            && self.region_filter.is_none()
            && self.exclude_regions.is_empty()
            && self.task_filter.is_none()
            && (self.sample_rate - 1.0).abs() < f64::EPSILON
            && self.custom.is_none()
    }

    /// Performs a sampling decision.
    ///
    /// Uses a simple xorshift for fast, reproducible sampling.
    fn sample(&mut self) -> bool {
        // xorshift64 — avoid the zero fixed-point
        let mut x = self.sample_state;
        if x == 0 {
            x = 1;
        }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.sample_state = x;

        // Convert to [0, 1) range without precision loss
        // Use high 53 bits to avoid f64 precision issues
        let normalized = ((x >> 11) as f64) / ((1u64 << 53) as f64);
        normalized < self.sample_rate
    }

    // =========================================================================
    // Inspection
    // =========================================================================

    /// Returns true if this filter includes the given event kind.
    #[must_use]
    pub fn includes_kind(&self, kind: EventCategory) -> bool {
        !self.exclude_kinds.contains(&kind)
            && (self.include_kinds.is_empty() || self.include_kinds.contains(&kind))
    }

    /// Returns the configured sample rate.
    #[must_use]
    pub fn sample_rate(&self) -> f64 {
        self.sample_rate
    }

    /// Returns the included kinds (empty = all).
    #[must_use]
    pub fn included_kinds(&self) -> &BTreeSet<EventCategory> {
        &self.include_kinds
    }

    /// Returns the excluded kinds.
    #[must_use]
    pub fn excluded_kinds(&self) -> &BTreeSet<EventCategory> {
        &self.exclude_kinds
    }

    /// Returns explicitly excluded regions.
    #[must_use]
    pub fn excluded_regions(&self) -> &BTreeSet<RegionId> {
        &self.exclude_regions
    }
}

// =============================================================================
// FilterBuilder (for Lab runtime integration)
// =============================================================================

/// Builder for configuring trace filters with a fluent API.
///
/// This is designed for integration with `LabRuntimeBuilder`:
///
/// ```ignore
/// let lab = LabRuntimeBuilder::new()
///     .record_trace()
///     .trace_filter(|f| f
///         .include_kinds([EventCategory::Scheduling, EventCategory::Time])
///         .exclude_region(RegionId(0))
///         .sample_rate(0.1))
///     .build();
/// ```
#[derive(Default)]
pub struct FilterBuilder {
    filter: TraceFilter,
}

impl FilterBuilder {
    /// Creates a new filter builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Includes the given event kinds.
    #[must_use]
    pub fn include_kinds<I>(mut self, kinds: I) -> Self
    where
        I: IntoIterator<Item = EventCategory>,
    {
        self.filter = self.filter.include_kinds(kinds);
        self
    }

    /// Excludes the given event kinds.
    #[must_use]
    pub fn exclude_kinds<I>(mut self, kinds: I) -> Self
    where
        I: IntoIterator<Item = EventCategory>,
    {
        self.filter = self.filter.exclude_kinds(kinds);
        self
    }

    /// Excludes the root region (useful for reducing noise).
    #[must_use]
    pub fn exclude_root_region(mut self) -> Self {
        self.filter = self.filter.exclude_region(RegionId::testing_default());
        self
    }

    /// Sets the sample rate for high-frequency events.
    #[must_use]
    pub fn sample_rate(mut self, rate: f64) -> Self {
        self.filter = self.filter.with_sample_rate(rate);
        self
    }

    /// Builds the filter.
    #[must_use]
    pub fn build(self) -> TraceFilter {
        self.filter
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[path = "filter_inline_tests.rs"]
mod tests;
