//! Stream Scheduler
//!
//! Implements priority-based scheduling for ATP streams with fair queuing
//! within priority classes and starvation protection.

use super::{StreamId, StreamPriority};
use std::collections::{HashMap, VecDeque};

const PRIORITY_LEVELS: usize = 5;
const MAX_STRICT_PRIORITY_BURST: usize = 8;

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
    /// Last priority class selected by `next_stream`.
    last_scheduled_priority: Option<usize>,
    /// Consecutive schedules from `last_scheduled_priority`.
    priority_burst_len: usize,
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
            last_scheduled_priority: None,
            priority_burst_len: 0,
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
        let Some(priority_index) = self.next_priority_index() else {
            self.last_scheduled_priority = None;
            self.priority_burst_len = 0;
            return None;
        };

        let stream_id = self.next_stream_in_priority(priority_index)?;
        self.record_scheduled_priority(priority_index);
        self.scheduled_count += 1;

        Some(stream_id)
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

    fn next_priority_index(&self) -> Option<usize> {
        if let Some(last_priority) = self.last_scheduled_priority
            && self.priority_burst_len >= MAX_STRICT_PRIORITY_BURST
            && let Some(priority_index) =
                ((last_priority + 1)..PRIORITY_LEVELS).find(|&index| self.priority_has_ready(index))
        {
            return Some(priority_index);
        }

        (0..PRIORITY_LEVELS).find(|&index| self.priority_has_ready(index))
    }

    fn priority_has_ready(&self, priority_index: usize) -> bool {
        self.priority_queues
            .get(priority_index)
            .is_some_and(|queue| queue.iter().any(|stream_id| self.is_ready(*stream_id)))
    }

    fn next_stream_in_priority(&mut self, priority_index: usize) -> Option<StreamId> {
        let queue_len = self.priority_queues[priority_index].len();
        if queue_len == 0 {
            return None;
        }

        let start_index = self.round_robin_index[priority_index] % queue_len;
        for i in 0..queue_len {
            let index = (start_index + i) % queue_len;
            let Some(&stream_id) = self.priority_queues[priority_index].get(index) else {
                continue;
            };
            if !self.is_ready(stream_id) {
                continue;
            }

            self.round_robin_index[priority_index] = (index + 1) % queue_len;
            return Some(stream_id);
        }

        None
    }

    fn record_scheduled_priority(&mut self, priority_index: usize) {
        if self.last_scheduled_priority == Some(priority_index) {
            self.priority_burst_len = self.priority_burst_len.saturating_add(1);
        } else {
            self.last_scheduled_priority = Some(priority_index);
            self.priority_burst_len = 1;
        }
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
#[path = "scheduler_inline_tests.rs"]
mod tests;
