import sys

with open('src/channel/flow_control_monitor.rs', 'r') as f:
    content = f.read()

# 1. Add total_blocked_time_ms to FlowControlMonitor
content = content.replace(
    '''    stats: FlowControlStats,
    /// Total events processed.
    total_events: AtomicU64,
}''',
    '''    stats: FlowControlStats,
    /// Cumulative blocked time for all tasks.
    total_blocked_time_ms: u64,
    /// Total events processed.
    total_events: AtomicU64,
}'''
)

# 2. Initialize it in new
content = content.replace(
    '''            deadlock_detector: DeadlockDetector::new(),
            stats: FlowControlStats::default(),
            total_events: AtomicU64::new(0),''',
    '''            deadlock_detector: DeadlockDetector::new(),
            stats: FlowControlStats::default(),
            total_blocked_time_ms: 0,
            total_events: AtomicU64::new(0),'''
)

# 3. Update total_blocked_time_ms in ProducerUnblocked
content = content.replace(
    '''            FlowControlEvent::ProducerUnblocked {
                channel_id,
                task_id,
                blocked_duration_ms,
                ..
            } => {
                if let Some(task_state) = self.task_states.get_mut(task_id) {''',
    '''            FlowControlEvent::ProducerUnblocked {
                channel_id,
                task_id,
                blocked_duration_ms,
                ..
            } => {
                self.total_blocked_time_ms += *blocked_duration_ms;
                if let Some(task_state) = self.task_states.get_mut(task_id) {'''
)

# 4. Update total_blocked_time_ms in ReserveUnblocked
content = content.replace(
    '''            FlowControlEvent::ReserveUnblocked {
                channel_id,
                task_id,
                permit_id,
                blocked_duration_ms,
                ..
            } => {
                if let Some(task_state) = self.task_states.get_mut(task_id) {''',
    '''            FlowControlEvent::ReserveUnblocked {
                channel_id,
                task_id,
                permit_id,
                blocked_duration_ms,
                ..
            } => {
                self.total_blocked_time_ms += *blocked_duration_ms;
                if let Some(task_state) = self.task_states.get_mut(task_id) {'''
)

# 5. Fix stats() avg calculation
content = content.replace(
    '''        // Calculate average block time
        if stats.total_events > 0 {
            let total_block_time: u64 = self
                .task_states
                .values()
                .map(|state| state.total_blocked_time_ms)
                .sum();
            stats.avg_block_time_ms = total_block_time / stats.total_events.max(1);
        }''',
    '''        // Calculate average block time
        if stats.total_events > 0 {
            stats.avg_block_time_ms = self.total_blocked_time_ms / stats.total_events.max(1);
        }'''
)

# 6. Fix memory leak in cleanup_old_state
content = content.replace(
    '''        // Remove old task states for completed/cancelled tasks
        self.task_states.retain(|_, state| {
            if state.blocked_channels.is_empty() {
                if let Some(cancel_time) = state.cancel_time {
                    cancel_time.as_nanos() >= cutoff_time.as_nanos()
                } else {
                    // Keep active states
                    true
                }
            } else {
                // Keep blocked states
                true
            }
        });''',
    '''        // Remove old task states to prevent memory growth
        self.task_states.retain(|_, state| {
            if !state.blocked_channels.is_empty() || !state.pending_permits.is_empty() {
                true
            } else if let Some(cancel_time) = state.cancel_time {
                cancel_time.as_nanos() >= cutoff_time.as_nanos()
            } else {
                false
            }
        });'''
)

# 7. Refactor record_event, check_violations_after_event, check_atomicity to fix the bounded-queue false-positive bug
old_record_event = '''    pub fn record_event(&mut self, event: FlowControlEvent) {
        if !self.config.enable_verification {
            return;
        }

        self.total_events.fetch_add(1, Ordering::Relaxed);

        // Update state based on event type
        self.update_state_from_event(&event);

        // Check for violations after state update
        self.check_violations_after_event(&event);

        // Store event with size limits
        self.events.push_back(event);
        while self.events.len() > self.config.max_tracked_events {
            self.events.pop_front();
        }

        self.stats.total_events += 1;
    }'''

new_record_event = '''    pub fn record_event(&mut self, event: FlowControlEvent) {
        if !self.config.enable_verification {
            return;
        }

        self.total_events.fetch_add(1, Ordering::Relaxed);

        let current_time = match &event {
            FlowControlEvent::ProducerBlocked { timestamp, .. } => *timestamp,
            FlowControlEvent::ProducerUnblocked { timestamp, .. } => *timestamp,
            FlowControlEvent::BackpressureApplied { timestamp, .. } => *timestamp,
            FlowControlEvent::BackpressureReleased { timestamp, .. } => *timestamp,
            FlowControlEvent::ReserveBlocked { timestamp, .. } => *timestamp,
            FlowControlEvent::ReserveUnblocked { timestamp, .. } => *timestamp,
            FlowControlEvent::CommitFlowControlled { timestamp, .. } => *timestamp,
            FlowControlEvent::AbortDueToFlowControl { timestamp, .. } => *timestamp,
        };

        // Check atomicity before state update so we can see pending permits
        self.check_atomicity(&event, current_time);

        // Update state based on event type
        self.update_state_from_event(&event);

        // Check for violations after state update
        self.check_violations_after_event(&event, current_time);

        // Store event with size limits
        self.events.push_back(event);
        while self.events.len() > self.config.max_tracked_events {
            self.events.pop_front();
        }

        self.stats.total_events += 1;
    }'''
content = content.replace(old_record_event, new_record_event)

old_check_violations_after = '''    fn check_violations_after_event(&mut self, event: &FlowControlEvent) {
        let current_time = match event {
            FlowControlEvent::ProducerBlocked { timestamp, .. } => *timestamp,
            FlowControlEvent::ProducerUnblocked { timestamp, .. } => *timestamp,
            FlowControlEvent::BackpressureApplied { timestamp, .. } => *timestamp,
            FlowControlEvent::BackpressureReleased { timestamp, .. } => *timestamp,
            FlowControlEvent::ReserveBlocked { timestamp, .. } => *timestamp,
            FlowControlEvent::ReserveUnblocked { timestamp, .. } => *timestamp,
            FlowControlEvent::CommitFlowControlled { timestamp, .. } => *timestamp,
            FlowControlEvent::AbortDueToFlowControl { timestamp, .. } => *timestamp,
        };

        // Check for potential deadlocks
        if self.config.enable_deadlock_prevention {
            let deadlocks = self.deadlock_detector.detect_deadlocks(current_time);
            for violation in deadlocks {
                self.record_violation(violation, current_time);
            }
        }

        // Check for starvation
        self.check_starvation(current_time);

        // Check for indefinite blocking
        self.check_indefinite_blocking(current_time);

        // Check for cancelled tasks that stayed blocked under flow control.
        self.check_cancellation_unblock_failures(current_time);

        // Check reserve/commit/abort atomicity for two-phase sends.
        self.check_atomicity(event, current_time);
    }'''

new_check_violations_after = '''    fn check_violations_after_event(&mut self, _event: &FlowControlEvent, current_time: Time) {
        // Check for potential deadlocks
        if self.config.enable_deadlock_prevention {
            let deadlocks = self.deadlock_detector.detect_deadlocks(current_time);
            for violation in deadlocks {
                self.record_violation(violation, current_time);
            }
        }

        // Check for starvation
        self.check_starvation(current_time);

        // Check for indefinite blocking
        self.check_indefinite_blocking(current_time);

        // Check for cancelled tasks that stayed blocked under flow control.
        self.check_cancellation_unblock_failures(current_time);
    }'''
content = content.replace(old_check_violations_after, new_check_violations_after)

old_check_atomicity = '''    fn check_atomicity(&mut self, event: &FlowControlEvent, current_time: Time) {
        match event {
            FlowControlEvent::CommitFlowControlled {
                channel_id,
                task_id,
                permit_id,
                ..
            } => {
                let has_pending_permit = self
                    .task_states
                    .get(task_id)
                    .is_some_and(|task_state| task_state.pending_permits.contains(permit_id));

                if !has_pending_permit {
                    self.record_violation(
                        FlowControlViolation::AtomicityViolation {
                            channel_id: *channel_id,
                            task_id: *task_id,
                            permit_id: *permit_id,
                            violation_type: "commit_flow_controlled_without_pending_reserve"
                                .to_string(),
                            timestamp: current_time,
                        },
                        current_time,
                    );
                }
            }
            FlowControlEvent::AbortDueToFlowControl {
                channel_id,
                task_id,
                permit_id,
                ..
            } => {
                let saw_reserve_block = self.events.iter().rev().any(|past_event| {
                    matches!(
                        past_event,
                        FlowControlEvent::ReserveBlocked {
                            channel_id: past_channel_id,
                            task_id: past_task_id,
                            permit_id: past_permit_id,
                            ..
                        } if past_channel_id == channel_id
                            && past_task_id == task_id
                            && past_permit_id == permit_id
                    )
                });

                if !saw_reserve_block {
                    self.record_violation(
                        FlowControlViolation::AtomicityViolation {
                            channel_id: *channel_id,
                            task_id: *task_id,
                            permit_id: *permit_id,
                            violation_type: "abort_without_pending_reserve".to_string(),
                            timestamp: current_time,
                        },
                        current_time,
                    );
                }
            }
            _ => {}
        }
    }'''

new_check_atomicity = '''    fn check_atomicity(&mut self, event: &FlowControlEvent, current_time: Time) {
        match event {
            FlowControlEvent::CommitFlowControlled {
                channel_id,
                task_id,
                permit_id,
                ..
            } => {
                let has_pending_permit = self
                    .task_states
                    .get(task_id)
                    .is_some_and(|task_state| task_state.pending_permits.contains(permit_id));

                if !has_pending_permit {
                    self.record_violation(
                        FlowControlViolation::AtomicityViolation {
                            channel_id: *channel_id,
                            task_id: *task_id,
                            permit_id: *permit_id,
                            violation_type: "commit_flow_controlled_without_pending_reserve"
                                .to_string(),
                            timestamp: current_time,
                        },
                        current_time,
                    );
                }
            }
            FlowControlEvent::AbortDueToFlowControl {
                channel_id,
                task_id,
                permit_id,
                ..
            } => {
                let has_pending_permit = self
                    .task_states
                    .get(task_id)
                    .is_some_and(|task_state| task_state.pending_permits.contains(permit_id));

                if !has_pending_permit {
                    self.record_violation(
                        FlowControlViolation::AtomicityViolation {
                            channel_id: *channel_id,
                            task_id: *task_id,
                            permit_id: *permit_id,
                            violation_type: "abort_without_pending_reserve".to_string(),
                            timestamp: current_time,
                        },
                        current_time,
                    );
                }
            }
            _ => {}
        }
    }'''
content = content.replace(old_check_atomicity, new_check_atomicity)

with open('src/channel/flow_control_monitor.rs', 'w') as f:
    f.write(content)
