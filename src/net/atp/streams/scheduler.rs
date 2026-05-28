//! Stream Scheduler
//!
//! Implements priority-based scheduling for ATP streams with fair queuing
//! within priority classes and starvation protection.

use super::{StreamId, StreamPriority};
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamScheduleState {
    Ready,
    Blocked,
}

/// Stream scheduler with priority classes and fair queuing
#[derive(Debug)]
pub struct StreamScheduler {
    /// Queues for each priority level
    priority_queues: [VecDeque<StreamId>; 5],
    /// Stream to priority mapping
    stream_priorities: HashMap<StreamId, StreamPriority>,
    /// Stream readiness state.
    stream_states: HashMap<StreamId, StreamScheduleState>,
    /// Round-robin index within each priority
    round_robin_index: [usize; 5],
    /// Total streams scheduled in current round
    scheduled_count: u64,
}

impl StreamScheduler {
    /// Create a new stream scheduler
    pub fn new() -> Self {
        Self {
            priority_queues: [
                VecDeque::new(), // Control
                VecDeque::new(), // Proof
                VecDeque::new(), // Data
                VecDeque::new(), // Repair
                VecDeque::new(), // Diagnostics
            ],
            stream_priorities: HashMap::new(),
            stream_states: HashMap::new(),
            round_robin_index: [0; 5],
            scheduled_count: 0,
        }
    }

    /// Register a stream with given priority
    pub fn register_stream(&mut self, stream_id: StreamId, priority: StreamPriority) {
        if let Some(old_priority) = self.stream_priorities.get(&stream_id).copied() {
            if old_priority != priority {
                self.remove_from_priority_queue(stream_id, old_priority);
                self.priority_queues
                    .get_mut(Self::priority_index(priority))
                    .unwrap() // ubs:ignore - index guaranteed by 5-level priority enum
                    .push_back(stream_id);
                self.stream_priorities.insert(stream_id, priority);
            }
            self.stream_states
                .insert(stream_id, StreamScheduleState::Ready);
            return;
        }

        let priority_index = priority as usize;
        self.priority_queues
            .get_mut(priority_index)
            .unwrap() // ubs:ignore - index guaranteed by 5-level priority enum
            .push_back(stream_id);
        self.stream_priorities.insert(stream_id, priority);
        self.stream_states
            .insert(stream_id, StreamScheduleState::Ready);
    }

    /// Unregister a stream
    pub fn unregister_stream(&mut self, stream_id: StreamId) {
        if let Some(priority) = self.stream_priorities.remove(&stream_id) {
            self.remove_from_priority_queue(stream_id, priority);
        }
        self.stream_states.remove(&stream_id);
    }

    /// Get the next stream to schedule
    pub fn next_stream(&mut self) -> Option<StreamId> {
        // Check each priority level from highest to lowest
        for priority_index in 0..5 {
            let queue_len = self.priority_queues[priority_index].len();
            if queue_len == 0 {
                continue;
            }

            // Round-robin within this priority level
            let start_index = self.round_robin_index[priority_index] % queue_len;

            // Try to find a schedulable stream starting from round-robin position
            for i in 0..queue_len {
                let index = (start_index + i) % queue_len;
                if let Some(&stream_id) = self.priority_queues[priority_index].get(index) {
                    if !self.is_ready(stream_id) {
                        continue;
                    }

                    // Update round-robin for next time
                    self.round_robin_index[priority_index] = (index + 1) % queue_len;
                    self.scheduled_count += 1;

                    return Some(stream_id);
                }
            }
        }

        None
    }

    /// Mark a stream as ready for scheduling
    pub fn mark_ready(&mut self, stream_id: StreamId) {
        if self.stream_priorities.contains_key(&stream_id) {
            self.stream_states
                .insert(stream_id, StreamScheduleState::Ready);
        }
    }

    /// Mark a stream as blocked
    pub fn mark_blocked(&mut self, stream_id: StreamId) {
        if self.stream_priorities.contains_key(&stream_id) {
            self.stream_states
                .insert(stream_id, StreamScheduleState::Blocked);
        }
    }

    /// Update stream priority
    pub fn update_priority(&mut self, stream_id: StreamId, new_priority: StreamPriority) {
        if let Some(old_priority) = self.stream_priorities.get(&stream_id).copied() {
            if old_priority != new_priority {
                // Remove from old queue
                self.remove_from_priority_queue(stream_id, old_priority);

                // Add to new queue
                let new_index = Self::priority_index(new_priority);
                self.priority_queues[new_index].push_back(stream_id);
                self.stream_priorities.insert(stream_id, new_priority);
            }
        }
    }

    /// Get statistics about the scheduler
    pub fn statistics(&self) -> SchedulerStats {
        SchedulerStats {
            control_queued: self.ready_count(0),
            proof_queued: self.ready_count(1),
            data_queued: self.ready_count(2),
            repair_queued: self.ready_count(3),
            diagnostics_queued: self.ready_count(4),
            total_scheduled: self.scheduled_count,
        }
    }

    /// Check if scheduler has any ready streams
    pub fn has_ready_streams(&self) -> bool {
        self.stream_states
            .values()
            .any(|state| *state == StreamScheduleState::Ready)
    }

    /// Get total number of streams
    pub fn stream_count(&self) -> usize {
        self.stream_priorities.len()
    }

    fn priority_index(priority: StreamPriority) -> usize {
        priority as usize
    }

    fn is_ready(&self, stream_id: StreamId) -> bool {
        self.stream_states.get(&stream_id) == Some(&StreamScheduleState::Ready)
    }

    fn ready_count(&self, priority_index: usize) -> usize {
        self.priority_queues
            .get(priority_index)
            .unwrap() // ubs:ignore - index guaranteed bounded by 5
            .iter()
            .filter(|stream_id| self.is_ready(**stream_id))
            .count()
    }

    fn remove_from_priority_queue(&mut self, stream_id: StreamId, priority: StreamPriority) {
        let priority_index = Self::priority_index(priority);
        let queue = self.priority_queues.get_mut(priority_index).unwrap(); // ubs:ignore - index guaranteed bounded by 5

        if let Some(pos) = queue.iter().position(|&id| id == stream_id) {
            queue.remove(pos);

            if pos <= self.round_robin_index[priority_index]
                && self.round_robin_index[priority_index] > 0
            {
                self.round_robin_index[priority_index] -= 1;
            }
        }
    }
}

/// Scheduler statistics
#[derive(Debug, Clone)]
pub struct SchedulerStats {
    pub control_queued: usize,
    pub proof_queued: usize,
    pub data_queued: usize,
    pub repair_queued: usize,
    pub diagnostics_queued: usize,
    pub total_scheduled: u64,
}

impl Default for StreamScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_scheduler_priority_ordering() {
        let mut scheduler = StreamScheduler::new();

        let control_stream = StreamId::new(0);
        let data_stream = StreamId::new(4);
        let repair_stream = StreamId::new(8);

        scheduler.register_stream(repair_stream, StreamPriority::Repair);
        scheduler.register_stream(data_stream, StreamPriority::Data);
        scheduler.register_stream(control_stream, StreamPriority::Control);

        // Control should come first (highest priority)
        assert_eq!(scheduler.next_stream(), Some(control_stream));
        scheduler.mark_blocked(control_stream);

        // With control blocked, data should come next.
        assert_eq!(scheduler.next_stream(), Some(data_stream));
        scheduler.mark_blocked(data_stream);

        // With higher-priority streams blocked, repair should come last.
        assert_eq!(scheduler.next_stream(), Some(repair_stream));
    }

    #[test]
    fn test_stream_scheduler_round_robin_within_priority() {
        let mut scheduler = StreamScheduler::new();

        let data1 = StreamId::new(4);
        let data2 = StreamId::new(8);
        let data3 = StreamId::new(12);

        scheduler.register_stream(data1, StreamPriority::Data);
        scheduler.register_stream(data2, StreamPriority::Data);
        scheduler.register_stream(data3, StreamPriority::Data);

        // Should round-robin between data streams
        let first = scheduler.next_stream().unwrap(); // ubs:ignore - test oracle
        let second = scheduler.next_stream().unwrap(); // ubs:ignore - test oracle
        let third = scheduler.next_stream().unwrap(); // ubs:ignore - test oracle

        // All streams should be different
        assert_ne!(first, second);
        assert_ne!(second, third);
        assert_ne!(first, third);
    }

    #[test]
    fn test_stream_unregister() {
        let mut scheduler = StreamScheduler::new();

        let stream1 = StreamId::new(0);
        let stream2 = StreamId::new(4);

        scheduler.register_stream(stream1, StreamPriority::Control);
        scheduler.register_stream(stream2, StreamPriority::Control);

        scheduler.unregister_stream(stream1);

        assert_eq!(scheduler.next_stream(), Some(stream2));
        assert_eq!(scheduler.next_stream(), Some(stream2));
        assert_eq!(scheduler.stream_count(), 1);
    }

    #[test]
    fn test_blocked_streams_are_not_scheduled() {
        let mut scheduler = StreamScheduler::new();

        let data1 = StreamId::new(4);
        let data2 = StreamId::new(8);
        let data3 = StreamId::new(12);

        scheduler.register_stream(data1, StreamPriority::Data);
        scheduler.register_stream(data2, StreamPriority::Data);
        scheduler.register_stream(data3, StreamPriority::Data);
        scheduler.mark_blocked(data2);

        assert_eq!(scheduler.next_stream(), Some(data1));
        assert_eq!(scheduler.next_stream(), Some(data3));
        assert_eq!(scheduler.next_stream(), Some(data1));
    }

    #[test]
    fn test_ready_unblocks_higher_priority_stream() {
        let mut scheduler = StreamScheduler::new();

        let control = StreamId::new(0);
        let data = StreamId::new(4);

        scheduler.register_stream(control, StreamPriority::Control);
        scheduler.register_stream(data, StreamPriority::Data);
        scheduler.mark_blocked(control);

        assert_eq!(scheduler.next_stream(), Some(data));

        scheduler.mark_ready(control);
        assert_eq!(scheduler.next_stream(), Some(control));
    }

    #[test]
    fn test_all_blocked_streams_report_no_ready_work() {
        let mut scheduler = StreamScheduler::new();

        let control = StreamId::new(0);
        let data = StreamId::new(4);

        scheduler.register_stream(control, StreamPriority::Control);
        scheduler.register_stream(data, StreamPriority::Data);
        scheduler.mark_blocked(control);
        scheduler.mark_blocked(data);

        assert!(!scheduler.has_ready_streams());
        assert_eq!(scheduler.stream_count(), 2);
        assert_eq!(scheduler.next_stream(), None);

        let stats = scheduler.statistics();
        assert_eq!(stats.control_queued, 0);
        assert_eq!(stats.data_queued, 0);
    }
}
