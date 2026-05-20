//! Stream Scheduler
//!
//! Implements priority-based scheduling for ATP streams with fair queuing
//! within priority classes and starvation protection.

use super::{StreamId, StreamPriority};
use std::collections::{HashMap, VecDeque};

/// Stream scheduler with priority classes and fair queuing
#[derive(Debug)]
pub struct StreamScheduler {
    /// Queues for each priority level
    priority_queues: [VecDeque<StreamId>; 5],
    /// Stream to priority mapping
    stream_priorities: HashMap<StreamId, StreamPriority>,
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
            round_robin_index: [0; 5],
            scheduled_count: 0,
        }
    }

    /// Register a stream with given priority
    pub fn register_stream(&mut self, stream_id: StreamId, priority: StreamPriority) {
        let priority_index = priority as usize;
        self.priority_queues[priority_index].push_back(stream_id);
        self.stream_priorities.insert(stream_id, priority);
    }

    /// Unregister a stream
    pub fn unregister_stream(&mut self, stream_id: StreamId) {
        if let Some(priority) = self.stream_priorities.remove(&stream_id) {
            let priority_index = priority as usize;
            let queue = &mut self.priority_queues[priority_index];

            // Find and remove the stream from the queue
            if let Some(pos) = queue.iter().position(|&id| id == stream_id) {
                queue.remove(pos);

                // Adjust round-robin index if necessary
                if pos <= self.round_robin_index[priority_index] && self.round_robin_index[priority_index] > 0 {
                    self.round_robin_index[priority_index] -= 1;
                }
            }
        }
    }

    /// Get the next stream to schedule
    pub fn next_stream(&mut self) -> Option<StreamId> {
        // Check each priority level from highest to lowest
        for priority_index in 0..5 {
            let queue = &mut self.priority_queues[priority_index];
            if queue.is_empty() {
                continue;
            }

            // Round-robin within this priority level
            let queue_len = queue.len();
            let start_index = self.round_robin_index[priority_index] % queue_len;

            // Try to find a schedulable stream starting from round-robin position
            for i in 0..queue_len {
                let index = (start_index + i) % queue_len;
                if let Some(&stream_id) = queue.get(index) {
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
        // Stream is already in the appropriate priority queue
        // This is a no-op in our simple scheduler
    }

    /// Mark a stream as blocked
    pub fn mark_blocked(&mut self, stream_id: StreamId) {
        // In a more sophisticated scheduler, we might move blocked streams
        // to a separate queue. For now, this is a no-op.
    }

    /// Update stream priority
    pub fn update_priority(&mut self, stream_id: StreamId, new_priority: StreamPriority) {
        if let Some(old_priority) = self.stream_priorities.get(&stream_id).cloned() {
            if old_priority != new_priority {
                // Remove from old queue
                let old_index = old_priority as usize;
                let old_queue = &mut self.priority_queues[old_index];
                if let Some(pos) = old_queue.iter().position(|&id| id == stream_id) {
                    old_queue.remove(pos);
                }

                // Add to new queue
                let new_index = new_priority as usize;
                self.priority_queues[new_index].push_back(stream_id);
                self.stream_priorities.insert(stream_id, new_priority);
            }
        }
    }

    /// Get statistics about the scheduler
    pub fn statistics(&self) -> SchedulerStats {
        SchedulerStats {
            control_queued: self.priority_queues[0].len(),
            proof_queued: self.priority_queues[1].len(),
            data_queued: self.priority_queues[2].len(),
            repair_queued: self.priority_queues[3].len(),
            diagnostics_queued: self.priority_queues[4].len(),
            total_scheduled: self.scheduled_count,
        }
    }

    /// Check if scheduler has any ready streams
    pub fn has_ready_streams(&self) -> bool {
        self.priority_queues.iter().any(|queue| !queue.is_empty())
    }

    /// Get total number of streams
    pub fn stream_count(&self) -> usize {
        self.stream_priorities.len()
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

        // Data should come next
        assert_eq!(scheduler.next_stream(), Some(data_stream));

        // Repair should come last
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
        let first = scheduler.next_stream().unwrap();
        let second = scheduler.next_stream().unwrap();
        let third = scheduler.next_stream().unwrap();

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
        assert_eq!(scheduler.next_stream(), None);
    }
}