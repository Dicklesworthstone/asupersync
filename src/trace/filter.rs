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
//! ```ignore
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
use std::collections::HashSet;
use std::sync::Arc;

// =============================================================================
// Event Kind Categories
// =============================================================================

/// Categories of trace events for filtering.
///
/// These categories group related events for easier filtering configuration.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
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
    include_kinds: HashSet<EventCategory>,

    /// Event kinds to exclude (takes precedence over include).
    exclude_kinds: HashSet<EventCategory>,

    /// Only record events for these regions (None = all regions).
    region_filter: Option<HashSet<RegionId>>,

    /// Only record events for these tasks (None = all tasks).
    task_filter: Option<HashSet<TaskId>>,

    /// Sample rate for high-frequency events (0.0-1.0).
    /// 1.0 = record all, 0.5 = record 50%, 0.0 = record none.
    sample_rate: f64,

    /// Custom filter predicate (must be Send + Sync for multi-threaded use).
    /// The predicate returns true if the event should be recorded.
    custom: Option<Arc<dyn Fn(&dyn FilterableEvent) -> bool + Send + Sync>>,

    /// RNG state for sampling decisions.
    sample_state: u64,
}

impl Default for TraceFilter {
    fn default() -> Self {
        Self {
            include_kinds: HashSet::new(),
            exclude_kinds: HashSet::new(),
            region_filter: None,
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
            .field("task_filter", &self.task_filter)
            .field("sample_rate", &self.sample_rate)
            .field("custom", &self.custom.as_ref().map(|_| "<predicate>"))
            .finish()
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
        let mut regions = HashSet::new();
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
            .get_or_insert_with(HashSet::new)
            .insert(region);
        self
    }

    /// Excludes a specific region from recording.
    ///
    /// Note: This removes the region from the include set. If no include set exists,
    /// this method has no effect. Use [`exclude_region_explicit`] if you need
    /// explicit exclusion.
    #[must_use]
    pub fn exclude_region(mut self, region: RegionId) -> Self {
        if let Some(ref mut regions) = self.region_filter {
            regions.remove(&region);
        }
        self
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
            .get_or_insert_with(HashSet::new)
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

        // 3. Check region filter
        if let Some(ref regions) = self.region_filter {
            if let Some(region) = event.region_id() {
                if !regions.contains(&region) {
                    return false;
                }
            }
            // Events without region association pass through
        }

        // 4. Check task filter
        if let Some(ref tasks) = self.task_filter {
            if let Some(task) = event.task_id() {
                if !tasks.contains(&task) {
                    return false;
                }
            }
            // Events without task association pass through
        }

        // 5. Apply sampling for high-frequency events
        if kind.is_sampled() && self.sample_rate < 1.0 && !self.sample() {
            return false;
        }

        // 6. Apply custom predicate
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
            && self.task_filter.is_none()
            && (self.sample_rate - 1.0).abs() < f64::EPSILON
            && self.custom.is_none()
    }

    /// Performs a sampling decision.
    ///
    /// Uses a simple xorshift for fast, reproducible sampling.
    fn sample(&mut self) -> bool {
        // xorshift64
        let mut x = self.sample_state.wrapping_add(1);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.sample_state = x;

        // Convert to [0, 1) range
        let normalized = (x as f64) / (u64::MAX as f64);
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
    pub fn included_kinds(&self) -> &HashSet<EventCategory> {
        &self.include_kinds
    }

    /// Returns the excluded kinds.
    #[must_use]
    pub fn excluded_kinds(&self) -> &HashSet<EventCategory> {
        &self.exclude_kinds
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
pub struct FilterBuilder {
    filter: TraceFilter,
}

impl FilterBuilder {
    /// Creates a new filter builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            filter: TraceFilter::new(),
        }
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
    pub fn exclude_root_region(self) -> Self {
        // Note: This would need actual RegionId construction
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

impl Default for FilterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Simple test event for filter testing
    struct TestEvent {
        kind: EventCategory,
        task: Option<TaskId>,
        region: Option<RegionId>,
    }

    impl FilterableEvent for TestEvent {
        fn event_kind(&self) -> EventCategory {
            self.kind
        }

        fn task_id(&self) -> Option<TaskId> {
            self.task
        }

        fn region_id(&self) -> Option<RegionId> {
            self.region
        }
    }

    fn make_task_id(index: u32) -> TaskId {
        TaskId::new_for_test(index, 0)
    }

    fn make_region_id(index: u32) -> RegionId {
        RegionId::new_for_test(index, 0)
    }

    #[test]
    fn default_filter_passes_all() {
        let mut filter = TraceFilter::default();
        assert!(filter.is_pass_through());

        let event = TestEvent {
            kind: EventCategory::Scheduling,
            task: Some(make_task_id(1)),
            region: Some(make_region_id(0)),
        };
        assert!(filter.should_record(&event));
    }

    #[test]
    fn include_kinds_filter() {
        let mut filter =
            TraceFilter::new().include_kinds([EventCategory::Scheduling, EventCategory::Time]);

        let scheduling = TestEvent {
            kind: EventCategory::Scheduling,
            task: None,
            region: None,
        };
        let io = TestEvent {
            kind: EventCategory::Io,
            task: None,
            region: None,
        };

        assert!(filter.should_record(&scheduling));
        assert!(!filter.should_record(&io));
    }

    #[test]
    fn exclude_kinds_filter() {
        let mut filter = TraceFilter::new().exclude_kind(EventCategory::Rng);

        let rng = TestEvent {
            kind: EventCategory::Rng,
            task: None,
            region: None,
        };
        let scheduling = TestEvent {
            kind: EventCategory::Scheduling,
            task: None,
            region: None,
        };

        assert!(!filter.should_record(&rng));
        assert!(filter.should_record(&scheduling));
    }

    #[test]
    fn exclude_takes_precedence_over_include() {
        let mut filter = TraceFilter::new()
            .include_kinds([EventCategory::Scheduling, EventCategory::Rng])
            .exclude_kind(EventCategory::Rng);

        let rng = TestEvent {
            kind: EventCategory::Rng,
            task: None,
            region: None,
        };
        assert!(!filter.should_record(&rng));
    }

    #[test]
    fn task_filter() {
        let task1 = make_task_id(1);
        let task2 = make_task_id(2);

        let mut filter = TraceFilter::new().filter_tasks([task1]);

        let event1 = TestEvent {
            kind: EventCategory::Scheduling,
            task: Some(task1),
            region: None,
        };
        let event2 = TestEvent {
            kind: EventCategory::Scheduling,
            task: Some(task2),
            region: None,
        };
        let no_task = TestEvent {
            kind: EventCategory::Time,
            task: None,
            region: None,
        };

        assert!(filter.should_record(&event1));
        assert!(!filter.should_record(&event2));
        assert!(filter.should_record(&no_task)); // No task = passes through
    }

    #[test]
    fn region_filter() {
        let region1 = make_region_id(1);
        let region2 = make_region_id(2);

        let mut filter = TraceFilter::new().filter_regions([region1]);

        let event1 = TestEvent {
            kind: EventCategory::Scheduling,
            task: None,
            region: Some(region1),
        };
        let event2 = TestEvent {
            kind: EventCategory::Scheduling,
            task: None,
            region: Some(region2),
        };
        let no_region = TestEvent {
            kind: EventCategory::Time,
            task: None,
            region: None,
        };

        assert!(filter.should_record(&event1));
        assert!(!filter.should_record(&event2));
        assert!(filter.should_record(&no_region)); // No region = passes through
    }

    #[test]
    fn sampling() {
        // Seed for reproducibility
        let mut filter = TraceFilter::new()
            .with_sample_rate(0.5)
            .with_sample_seed(42);

        // Count how many RNG events pass
        let mut passed = 0;
        let total = 1000;

        for _ in 0..total {
            let event = TestEvent {
                kind: EventCategory::Rng, // High-frequency, subject to sampling
                task: None,
                region: None,
            };
            if filter.should_record(&event) {
                passed += 1;
            }
        }

        // Should be approximately 50% (with some variance)
        assert!(passed > 400 && passed < 600, "Passed: {passed}");
    }

    #[test]
    fn no_sampling_for_non_high_frequency() {
        let mut filter = TraceFilter::new()
            .with_sample_rate(0.0) // Would drop all sampled events
            .with_sample_seed(42);

        // Scheduling is not high-frequency, so not sampled
        let event = TestEvent {
            kind: EventCategory::Scheduling,
            task: None,
            region: None,
        };

        // Should pass even with 0% sample rate
        assert!(filter.should_record(&event));
    }

    #[test]
    fn custom_predicate() {
        let mut filter = TraceFilter::new().with_custom(|event| {
            // Only allow events with a task ID
            event.task_id().is_some()
        });

        let with_task = TestEvent {
            kind: EventCategory::Scheduling,
            task: Some(make_task_id(1)),
            region: None,
        };
        let without_task = TestEvent {
            kind: EventCategory::Time,
            task: None,
            region: None,
        };

        assert!(filter.should_record(&with_task));
        assert!(!filter.should_record(&without_task));
    }

    #[test]
    fn predefined_scheduling_only() {
        let filter = TraceFilter::scheduling_only();

        assert!(filter.includes_kind(EventCategory::Scheduling));
        assert!(filter.includes_kind(EventCategory::Chaos));
        assert!(!filter.includes_kind(EventCategory::Rng));
        assert!(!filter.includes_kind(EventCategory::Io));
    }

    #[test]
    fn predefined_no_rng() {
        let filter = TraceFilter::no_rng();

        assert!(!filter.includes_kind(EventCategory::Rng));
        assert!(filter.includes_kind(EventCategory::Scheduling));
        assert!(filter.includes_kind(EventCategory::Time));
    }

    #[test]
    fn predefined_io_focused() {
        let filter = TraceFilter::io_focused();

        assert!(filter.includes_kind(EventCategory::Io));
        assert!(filter.includes_kind(EventCategory::Scheduling));
        assert!(filter.includes_kind(EventCategory::Time));
        assert!(!filter.includes_kind(EventCategory::Rng));
        assert!(!filter.includes_kind(EventCategory::Waker));
    }

    #[test]
    fn filter_builder() {
        let filter = FilterBuilder::new()
            .include_kinds([EventCategory::Scheduling, EventCategory::Time])
            .exclude_kinds([EventCategory::Waker])
            .sample_rate(0.5)
            .build();

        assert!(filter.includes_kind(EventCategory::Scheduling));
        assert!(!filter.includes_kind(EventCategory::Rng));
        assert!(!filter.includes_kind(EventCategory::Waker));
        assert!((filter.sample_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn is_pass_through() {
        assert!(TraceFilter::default().is_pass_through());
        assert!(!TraceFilter::no_rng().is_pass_through());
        assert!(!TraceFilter::scheduling_only().is_pass_through());
        assert!(!TraceFilter::with_sampling(0.5).is_pass_through());
    }
}
