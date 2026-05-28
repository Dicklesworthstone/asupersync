//! Stream priority integration for content-aware scheduling.
//!
//! This module provides integration between the content scheduler and
//! stream-level scheduling systems (like QUIC streams), ensuring that
//! high-priority content gets appropriate stream priority assignments.

use crate::runtime::scheduler::content::{ContentItem, PriorityClass};
use crate::types::Time;
use crate::util::det_hash::DetHashMap;
use serde::{Deserialize, Serialize};
use std::collections::BinaryHeap;

/// QUIC stream priority levels mapped from content priority classes.
///
/// Higher values = higher priority in QUIC stream scheduling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum StreamPriority {
    /// Background/bulk data transfers
    Background = 0,
    /// Normal data priority
    Normal = 1,
    /// Important data that should be expedited
    Important = 2,
    /// Critical control traffic
    Critical = 3,
}

impl StreamPriority {
    /// Maps content priority class to appropriate stream priority.
    #[must_use]
    pub fn from_content_class(class: PriorityClass) -> Self {
        match class {
            PriorityClass::Telemetry | PriorityClass::Prefetch => Self::Background,
            PriorityClass::Data | PriorityClass::Repair => Self::Normal,
            PriorityClass::Proof | PriorityClass::AckBitmap => Self::Important,
            PriorityClass::Control | PriorityClass::Manifest => Self::Critical,
        }
    }

    /// Returns the numeric priority value for stream schedulers.
    #[must_use]
    pub const fn value(self) -> u8 {
        self as u8
    }
}

/// Stream assignment for a piece of content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamAssignment {
    /// Stream ID assigned to this content
    pub stream_id: u64,
    /// Priority level for the stream
    pub priority: StreamPriority,
    /// Timestamp when assignment was made
    pub assigned_at: Time,
}

/// Stream scheduler that manages priority assignments and fairness.
#[derive(Debug)]
pub struct StreamPriorityScheduler {
    /// Next available stream ID
    next_stream_id: u64,
    /// Active stream assignments
    active_streams: DetHashMap<u64, StreamAssignment>,
    /// Priority-ordered queue of available stream IDs for reuse
    available_streams: BinaryHeap<AvailableStream>,
    /// Stream usage tracking for fairness
    stream_usage: DetHashMap<u64, StreamUsage>,
    /// Maximum number of concurrent streams
    max_concurrent_streams: usize,
}

/// Available stream for reuse.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AvailableStream {
    stream_id: u64,
    last_priority: StreamPriority,
    freed_at: Time,
}

impl PartialOrd for AvailableStream {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AvailableStream {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Higher priority streams are preferred for reuse
        self.last_priority
            .cmp(&other.last_priority)
            .then_with(|| other.freed_at.cmp(&self.freed_at)) // Earlier freed time preferred
            .then_with(|| self.stream_id.cmp(&other.stream_id)) // Deterministic tie-break
    }
}

/// Stream usage statistics for fairness tracking.
#[derive(Debug, Clone, PartialEq)]
pub struct StreamUsage {
    pub bytes_sent: u64,
    pub items_sent: usize,
    pub last_used: Time,
}

impl Default for StreamUsage {
    fn default() -> Self {
        Self {
            bytes_sent: 0,
            items_sent: 0,
            last_used: Time::ZERO,
        }
    }
}

impl Default for StreamPriorityScheduler {
    fn default() -> Self {
        Self::new(256) // Default max concurrent streams
    }
}

impl StreamPriorityScheduler {
    /// Creates a new stream priority scheduler.
    #[must_use]
    pub fn new(max_concurrent_streams: usize) -> Self {
        Self {
            next_stream_id: 1,
            active_streams: DetHashMap::default(),
            available_streams: BinaryHeap::new(),
            stream_usage: DetHashMap::default(),
            max_concurrent_streams: max_concurrent_streams.max(1),
        }
    }

    /// Assigns a stream to content, creating a new stream or reusing an existing one.
    ///
    /// Returns the stream assignment with stream ID and priority.
    pub fn assign_stream(&mut self, content: &ContentItem, now: Time) -> StreamAssignment {
        let priority = StreamPriority::from_content_class(content.priority_class);

        // Try to reuse an existing stream with compatible priority if available
        let stream_id = if let Some(existing_id) = content.stream_id {
            // Content already specifies a stream ID
            existing_id
        } else {
            // Find or allocate a stream
            self.find_or_allocate_stream(priority, now)
        };

        let assignment = StreamAssignment {
            stream_id,
            priority,
            assigned_at: now,
        };

        self.active_streams.insert(stream_id, assignment.clone());

        // Update usage tracking
        let usage = self.stream_usage.entry(stream_id).or_default();
        usage.bytes_sent += content.size_bytes as u64;
        usage.items_sent += 1;
        usage.last_used = now;

        assignment
    }

    /// Releases a stream when content transmission is complete.
    pub fn release_stream(&mut self, stream_id: u64, now: Time) {
        if let Some(assignment) = self.active_streams.remove(&stream_id) {
            // Add to available streams for potential reuse
            let available = AvailableStream {
                stream_id,
                last_priority: assignment.priority,
                freed_at: now,
            };
            self.available_streams.push(available);

            // Limit the size of available streams queue
            while self.available_streams.len() > self.max_concurrent_streams / 2 {
                self.available_streams.pop();
            }
        }
    }

    /// Returns the current stream assignment for a stream ID.
    #[must_use]
    pub fn get_stream_assignment(&self, stream_id: u64) -> Option<&StreamAssignment> {
        self.active_streams.get(&stream_id)
    }

    /// Returns the number of active streams.
    #[must_use]
    pub fn active_stream_count(&self) -> usize {
        self.active_streams.len()
    }

    /// Returns stream usage statistics for fairness monitoring.
    #[must_use]
    pub fn stream_usage(&self, stream_id: u64) -> Option<&StreamUsage> {
        self.stream_usage.get(&stream_id)
    }

    /// Returns all active stream assignments.
    #[must_use]
    pub fn active_streams(&self) -> &DetHashMap<u64, StreamAssignment> {
        &self.active_streams
    }

    /// Clears all stream assignments and resets state.
    pub fn clear(&mut self) {
        self.active_streams.clear();
        self.available_streams.clear();
        self.stream_usage.clear();
        self.next_stream_id = 1;
    }

    fn find_or_allocate_stream(&mut self, priority: StreamPriority, _now: Time) -> u64 {
        // Prefer an already-active stream with the same priority. Stream
        // priority is a lane, not a per-item allocation, so compatible content
        // should share the lane and accumulate usage statistics on the same
        // stream instead of consuming the stream limit unnecessarily.
        if let Some((stream_id, _, _, _)) = self
            .active_streams
            .iter()
            .filter_map(|(&stream_id, assignment)| {
                if assignment.priority != priority {
                    return None;
                }
                let usage = self.stream_usage.get(&stream_id);
                let bytes_sent = usage.map_or(0, |usage| usage.bytes_sent);
                let items_sent = usage.map_or(0, |usage| usage.items_sent);
                Some((stream_id, bytes_sent, items_sent, assignment.assigned_at))
            })
            .min_by_key(|(stream_id, bytes_sent, items_sent, assigned_at)| {
                (*bytes_sent, *items_sent, *assigned_at, *stream_id)
            })
        {
            return stream_id;
        }

        // Try to reuse an available stream with compatible priority
        while let Some(available) = self.available_streams.pop() {
            if available.last_priority == priority
                && !self.active_streams.contains_key(&available.stream_id)
            {
                return available.stream_id;
            }
        }

        // Allocate new stream if under limit
        if self.active_streams.len() < self.max_concurrent_streams {
            let stream_id = self.next_stream_id;
            self.next_stream_id += 1;
            return stream_id;
        }

        // If at limit, find the lowest priority active stream to reuse
        if let Some((&stream_id, _)) = self
            .active_streams
            .iter()
            .min_by_key(|(_, assignment)| (assignment.priority, assignment.assigned_at))
        {
            stream_id
        } else {
            // Fallback: allocate new stream anyway
            let stream_id = self.next_stream_id;
            self.next_stream_id += 1;
            stream_id
        }
    }
}

/// Integration helper for coordinating content and stream scheduling.
#[derive(Debug)]
pub struct SchedulerIntegration {
    content_scheduler: crate::runtime::scheduler::content::ContentScheduler,
    stream_scheduler: StreamPriorityScheduler,
}

impl Default for SchedulerIntegration {
    fn default() -> Self {
        Self::new()
    }
}

impl SchedulerIntegration {
    /// Creates a new integrated scheduler.
    #[must_use]
    pub fn new() -> Self {
        Self {
            content_scheduler: crate::runtime::scheduler::content::ContentScheduler::new(),
            stream_scheduler: StreamPriorityScheduler::new(256),
        }
    }

    /// Schedules content with automatic stream assignment.
    pub fn schedule_content(&mut self, mut content: ContentItem, now: Time) -> bool {
        // Assign stream if not already specified
        if content.stream_id.is_none() {
            let assignment = self.stream_scheduler.assign_stream(&content, now);
            content = content.with_stream_id(assignment.stream_id);
        }

        self.content_scheduler.schedule(content)
    }

    /// Gets the next content to transmit with stream priority information.
    pub fn next_content(
        &mut self,
        now: Time,
    ) -> Option<(
        ContentItem,
        StreamAssignment,
        crate::runtime::scheduler::content::ScheduleEvidence,
    )> {
        let (content, evidence) = self.content_scheduler.next_content(now)?;

        let assignment = if let Some(stream_id) = content.stream_id {
            self.stream_scheduler
                .get_stream_assignment(stream_id)
                .cloned()
                .unwrap_or_else(|| {
                    // Stream not found, assign a new one
                    self.stream_scheduler.assign_stream(&content, now)
                })
        } else {
            // Assign new stream
            self.stream_scheduler.assign_stream(&content, now)
        };

        Some((content, assignment, evidence))
    }

    /// Updates system pressure for content scheduling decisions.
    pub fn update_pressure(
        &mut self,
        pressure: crate::runtime::scheduler::content::PressureSnapshot,
    ) {
        self.content_scheduler.update_pressure(pressure);
    }

    /// Releases a stream when transmission is complete.
    pub fn release_stream(&mut self, stream_id: u64, now: Time) {
        self.stream_scheduler.release_stream(stream_id, now);
    }

    /// Returns scheduling statistics for monitoring.
    pub fn stats(&self) -> SchedulerStats {
        SchedulerStats {
            pending_content_count: self.content_scheduler.pending_count(),
            active_stream_count: self.stream_scheduler.active_stream_count(),
            evidence_log_size: self.content_scheduler.evidence_log().len(),
        }
    }

    /// Clears all scheduled content and stream assignments.
    pub fn clear(&mut self) {
        self.content_scheduler.clear();
        self.stream_scheduler.clear();
    }
}

/// Statistics for scheduler monitoring and tuning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulerStats {
    /// Number of content items pending transmission
    pub pending_content_count: usize,
    /// Number of active streams
    pub active_stream_count: usize,
    /// Number of entries in evidence log
    pub evidence_log_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::scheduler::content::{ContentId, ContentItem};

    fn test_content(id: u64, priority: PriorityClass, size: usize) -> ContentItem {
        ContentItem::new(ContentId::new(id), priority, size, 1.0, 1.0)
    }

    #[test]
    fn stream_priority_mapping() {
        assert_eq!(
            StreamPriority::from_content_class(PriorityClass::Control),
            StreamPriority::Critical
        );
        assert_eq!(
            StreamPriority::from_content_class(PriorityClass::Data),
            StreamPriority::Normal
        );
        assert_eq!(
            StreamPriority::from_content_class(PriorityClass::Telemetry),
            StreamPriority::Background
        );
    }

    #[test]
    fn stream_assignment_basic() {
        let mut scheduler = StreamPriorityScheduler::new(10);
        let content = test_content(1, PriorityClass::Control, 100);

        let assignment = scheduler.assign_stream(&content, Time::ZERO);

        assert_eq!(assignment.stream_id, 1);
        assert_eq!(assignment.priority, StreamPriority::Critical);
        assert_eq!(scheduler.active_stream_count(), 1);
    }

    #[test]
    fn stream_reuse() {
        let mut scheduler = StreamPriorityScheduler::new(2);

        let content1 = test_content(1, PriorityClass::Control, 100);
        let assignment1 = scheduler.assign_stream(&content1, Time::ZERO);

        // Release the stream
        scheduler.release_stream(assignment1.stream_id, Time::from_nanos(100));

        // Assign new content with same priority - should reuse stream
        let content2 = test_content(2, PriorityClass::Control, 200);
        let assignment2 = scheduler.assign_stream(&content2, Time::from_nanos(200));

        assert_eq!(assignment1.stream_id, assignment2.stream_id);
        assert_eq!(assignment2.priority, StreamPriority::Critical);
    }

    #[test]
    fn integrated_scheduler_basic() {
        let mut integrated = SchedulerIntegration::new();

        let content = test_content(1, PriorityClass::Data, 100);
        assert!(integrated.schedule_content(content, Time::ZERO));

        let stats = integrated.stats();
        assert_eq!(stats.pending_content_count, 1);
        assert_eq!(stats.active_stream_count, 1);

        let result = integrated.next_content(Time::ZERO);
        assert!(result.is_some());

        let (content, assignment, _evidence) = result.unwrap();
        assert_eq!(content.id.value(), 1);
        assert_eq!(assignment.priority, StreamPriority::Normal);
    }

    #[test]
    fn stream_usage_tracking() {
        let mut scheduler = StreamPriorityScheduler::new(10);

        let content1 = test_content(1, PriorityClass::Data, 100);
        let content2 = test_content(2, PriorityClass::Data, 200);

        let assignment1 = scheduler.assign_stream(&content1, Time::ZERO);
        let assignment2 = scheduler.assign_stream(&content2, Time::from_nanos(100));

        // Both should use the same stream (same priority)
        assert_eq!(assignment1.stream_id, assignment2.stream_id);

        let usage = scheduler.stream_usage(assignment1.stream_id).unwrap();
        assert_eq!(usage.bytes_sent, 300); // 100 + 200
        assert_eq!(usage.items_sent, 2);
    }
}
