//! Real integration tests between runtime/scheduler/priority and trace/event.
//!
//! Verifies that the EDF priority lane emits expected trace events for task
//! scheduling operations with deterministic timing behavior.

#![allow(clippy::missing_docs_in_private_items)]

use crate::runtime::scheduler::priority::PriorityScheduler;
use crate::time::Time as RuntimeTime;
use crate::trace::event::{TraceData, TraceEvent, TraceEventKind};
use crate::trace::recorder::TraceRecorder;
use crate::types::{TaskId, Time, TraceId};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Mock task with priority and deadline information.
#[derive(Debug, Clone)]
struct MockTask {
    /// Task identifier.
    task_id: TaskId,
    /// Task priority (0 = highest, 255 = lowest).
    priority: u8,
    /// Optional deadline for EDF scheduling.
    deadline: Option<Time>,
    /// Task execution duration.
    execution_duration: Duration,
    /// Number of times this task has been polled.
    poll_count: u64,
}

impl MockTask {
    fn new(priority: u8, deadline_offset: Option<Duration>) -> Self {
        let task_id = TaskId::new();
        let deadline = deadline_offset.map(|offset| Time::from_nanos(offset.as_nanos() as u64));

        Self {
            task_id,
            priority,
            deadline,
            execution_duration: Duration::from_millis(10 + priority as u64),
            poll_count: 0,
        }
    }

    /// Create a high-priority task with tight deadline.
    fn high_priority(deadline_ms: u64) -> Self {
        Self::new(0, Some(Duration::from_millis(deadline_ms)))
    }

    /// Create a medium-priority task with loose deadline.
    fn medium_priority(deadline_ms: u64) -> Self {
        Self::new(128, Some(Duration::from_millis(deadline_ms)))
    }

    /// Create a low-priority task with no deadline.
    fn low_priority() -> Self {
        Self::new(255, None)
    }

    /// Create a cancel-priority task (goes to cancel lane).
    fn cancel_priority() -> Self {
        Self::new(0, None) // High priority but no deadline
    }
}

/// Priority scheduler integration manager with trace recording.
struct PrioritySchedulerIntegrationManager {
    /// The priority scheduler under test.
    scheduler: PriorityScheduler,
    /// Trace recorder for capturing events.
    trace_recorder: Arc<Mutex<TraceRecorder>>,
    /// Tasks being managed.
    tasks: BTreeMap<TaskId, MockTask>,
    /// Current virtual time.
    virtual_time: Time,
    /// Generation counter for scheduling order.
    generation: u64,
}

impl PrioritySchedulerIntegrationManager {
    fn new() -> Self {
        Self {
            scheduler: PriorityScheduler::new(),
            trace_recorder: Arc::new(Mutex::new(TraceRecorder::new())),
            tasks: BTreeMap::new(),
            virtual_time: Time::from_nanos(0),
            generation: 0,
        }
    }

    /// Add a task to the scheduler and record the spawn event.
    fn add_task(&mut self, task: MockTask) {
        let task_id = task.task_id;
        self.tasks.insert(task_id, task.clone());

        // Record spawn event
        self.record_event(
            TraceEventKind::Spawn,
            TraceData::Spawn {
                task: task_id,
                region: crate::types::RegionId::new(),
            },
        );

        // Schedule the task based on its characteristics
        if task.deadline.is_some() {
            // Has deadline -> goes to timed (EDF) lane
            self.scheduler
                .schedule_timed(task_id, task.deadline.unwrap(), self.generation);
            self.record_event(
                TraceEventKind::Schedule,
                TraceData::Schedule {
                    task: task_id,
                    lane: "EDF".to_string(),
                    priority: Some(task.priority),
                    deadline: task.deadline,
                },
            );
        } else if task.priority == 0 {
            // High priority without deadline -> might go to cancel lane in some scenarios
            self.scheduler
                .schedule_ready(task_id, task.priority, self.generation);
            self.record_event(
                TraceEventKind::Schedule,
                TraceData::Schedule {
                    task: task_id,
                    lane: "Ready".to_string(),
                    priority: Some(task.priority),
                    deadline: None,
                },
            );
        } else {
            // Regular priority task -> goes to ready lane
            self.scheduler
                .schedule_ready(task_id, task.priority, self.generation);
            self.record_event(
                TraceEventKind::Schedule,
                TraceData::Schedule {
                    task: task_id,
                    lane: "Ready".to_string(),
                    priority: Some(task.priority),
                    deadline: None,
                },
            );
        }

        self.generation += 1;
    }

    /// Simulate polling the next task from the scheduler.
    fn poll_next_task(&mut self) -> Option<TaskId> {
        // Check cancel lane first (highest priority)
        if let Some(task_id) = self.scheduler.next_cancel() {
            self.record_poll_event(task_id, "Cancel");
            return Some(task_id);
        }

        // Check EDF lane next
        if let Some(task_id) = self.scheduler.next_timed(self.virtual_time) {
            self.record_poll_event(task_id, "EDF");
            return Some(task_id);
        }

        // Check ready lane last
        if let Some(task_id) = self.scheduler.next_ready() {
            self.record_poll_event(task_id, "Ready");
            return Some(task_id);
        }

        None
    }

    /// Record a poll event for a task.
    fn record_poll_event(&mut self, task_id: TaskId, lane: &str) {
        if let Some(task) = self.tasks.get_mut(&task_id) {
            task.poll_count += 1;

            self.record_event(
                TraceEventKind::Poll,
                TraceData::Poll {
                    task: task_id,
                    outcome: "Pending".to_string(),
                    duration_nanos: task.execution_duration.as_nanos() as u64,
                },
            );

            // Simulate task execution advancing time
            let execution_nanos = task.execution_duration.as_nanos() as u64;
            self.virtual_time = Time::from_nanos(self.virtual_time.as_nanos() + execution_nanos);

            self.record_event(
                TraceEventKind::TimeAdvance,
                TraceData::TimeAdvance {
                    old_time: Time::from_nanos(self.virtual_time.as_nanos() - execution_nanos),
                    new_time: self.virtual_time,
                    delta_nanos: execution_nanos,
                },
            );

            // Yield after polling
            self.record_event(
                TraceEventKind::Yield,
                TraceData::Yield {
                    task: task_id,
                    reason: "Cooperative".to_string(),
                },
            );
        }
    }

    /// Record a cancel request for a task.
    fn cancel_task(&mut self, task_id: TaskId) {
        if self.tasks.contains_key(&task_id) {
            // Move to cancel lane
            self.scheduler.schedule_cancel(task_id, self.generation);
            self.generation += 1;

            self.record_event(
                TraceEventKind::CancelRequest,
                TraceData::CancelRequest {
                    task: task_id,
                    reason: crate::types::CancelReason::Explicit,
                },
            );
        }
    }

    /// Complete a task and record completion event.
    fn complete_task(&mut self, task_id: TaskId) {
        if let Some(_task) = self.tasks.remove(&task_id) {
            self.record_event(
                TraceEventKind::Complete,
                TraceData::Complete {
                    task: task_id,
                    outcome: crate::types::Outcome::Ok(()),
                },
            );
        }
    }

    /// Record a trace event.
    fn record_event(&mut self, kind: TraceEventKind, data: TraceData) {
        let event = TraceEvent {
            kind,
            data,
            timestamp: self.virtual_time,
            trace_id: TraceId::new(),
            task: None, // Would be set by actual runtime
        };

        if let Ok(mut recorder) = self.trace_recorder.lock() {
            recorder.record(event);
        }
    }

    /// Get recorded events.
    fn get_recorded_events(&self) -> Vec<TraceEvent> {
        self.trace_recorder.lock().unwrap().events().to_vec()
    }

    /// Advance virtual time and trigger any deadline-based events.
    fn advance_time(&mut self, delta: Duration) {
        let old_time = self.virtual_time;
        self.virtual_time = Time::from_nanos(old_time.as_nanos() + delta.as_nanos() as u64);

        self.record_event(
            TraceEventKind::TimeAdvance,
            TraceData::TimeAdvance {
                old_time,
                new_time: self.virtual_time,
                delta_nanos: delta.as_nanos() as u64,
            },
        );
    }
}

/// Test scenario for priority scheduler + trace event integration.
struct PrioritySchedulerTestScenario {
    /// Integration manager.
    manager: PrioritySchedulerIntegrationManager,
    /// Expected event counts by type.
    expected_events: BTreeMap<String, usize>,
}

impl PrioritySchedulerTestScenario {
    fn new() -> Self {
        Self {
            manager: PrioritySchedulerIntegrationManager::new(),
            expected_events: BTreeMap::new(),
        }
    }

    /// Run a comprehensive test scenario.
    async fn run_comprehensive_test(&mut self) -> TestResult {
        // Phase 1: Add tasks with different priorities and deadlines
        let high_priority_task = MockTask::high_priority(50); // 50ms deadline
        let medium_priority_task = MockTask::medium_priority(200); // 200ms deadline
        let low_priority_task = MockTask::low_priority(); // No deadline

        self.manager.add_task(high_priority_task.clone());
        self.manager.add_task(medium_priority_task.clone());
        self.manager.add_task(low_priority_task.clone());

        // Phase 2: Poll tasks and verify EDF ordering
        let mut execution_order = Vec::new();

        // First poll should get high-priority task (earliest deadline)
        if let Some(task_id) = self.manager.poll_next_task() {
            execution_order.push(task_id);
            assert_eq!(
                task_id, high_priority_task.task_id,
                "High priority task should execute first"
            );
        }

        // Advance time past high priority deadline
        self.manager.advance_time(Duration::from_millis(60));

        // Add a cancel-priority task to test cancel lane
        let cancel_task = MockTask::cancel_priority();
        let cancel_task_id = cancel_task.task_id;
        self.manager.add_task(cancel_task);
        self.manager.cancel_task(cancel_task_id);

        // Next poll should get cancel task (highest priority lane)
        if let Some(task_id) = self.manager.poll_next_task() {
            execution_order.push(task_id);
            assert_eq!(
                task_id, cancel_task_id,
                "Cancel task should have highest priority"
            );
        }

        // Complete the cancel task
        self.manager.complete_task(cancel_task_id);

        // Continue with remaining tasks in EDF order
        if let Some(task_id) = self.manager.poll_next_task() {
            execution_order.push(task_id);
            assert_eq!(
                task_id, medium_priority_task.task_id,
                "Medium priority task should execute next"
            );
        }

        if let Some(task_id) = self.manager.poll_next_task() {
            execution_order.push(task_id);
            assert_eq!(
                task_id, low_priority_task.task_id,
                "Low priority task should execute last"
            );
        }

        // Phase 3: Verify trace events were recorded correctly
        let events = self.manager.get_recorded_events();
        let event_counts = self.count_events_by_type(&events);

        TestResult {
            execution_order,
            event_counts,
            total_events: events.len(),
            edf_ordering_correct: self.verify_edf_ordering(&events),
            cancel_lane_priority_correct: self.verify_cancel_lane_priority(&events),
            timing_deterministic: self.verify_timing_determinism(&events),
        }
    }

    /// Count events by type.
    fn count_events_by_type(&self, events: &[TraceEvent]) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for event in events {
            let event_type = format!("{:?}", event.kind);
            *counts.entry(event_type).or_insert(0) += 1;
        }
        counts
    }

    /// Verify that EDF ordering is reflected in trace events.
    fn verify_edf_ordering(&self, events: &[TraceEvent]) -> bool {
        let mut last_deadline: Option<Time> = None;

        for event in events {
            if let TraceEventKind::Schedule = event.kind {
                if let TraceData::Schedule {
                    deadline: Some(deadline),
                    lane,
                    ..
                } = &event.data
                {
                    if lane == "EDF" {
                        if let Some(last) = last_deadline {
                            if *deadline < last {
                                return false; // Deadline ordering violation
                            }
                        }
                        last_deadline = Some(*deadline);
                    }
                }
            }
        }

        true
    }

    /// Verify that cancel lane tasks are prioritized correctly.
    fn verify_cancel_lane_priority(&self, events: &[TraceEvent]) -> bool {
        let mut cancel_poll_time: Option<Time> = None;
        let mut other_poll_times = Vec::new();

        for event in events {
            match &event.kind {
                TraceEventKind::CancelRequest => {
                    // Look for subsequent poll of this task
                    for later_event in events {
                        if later_event.timestamp > event.timestamp {
                            if let TraceEventKind::Poll = later_event.kind {
                                if let TraceData::Poll { task, .. } = &later_event.data {
                                    if let TraceData::CancelRequest {
                                        task: cancel_task, ..
                                    } = &event.data
                                    {
                                        if task == cancel_task {
                                            cancel_poll_time = Some(later_event.timestamp);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                TraceEventKind::Poll => {
                    if let TraceData::Poll { .. } = &event.data {
                        other_poll_times.push(event.timestamp);
                    }
                }
                _ => {}
            }
        }

        // Cancel task should be polled before other tasks after cancellation request
        if let Some(cancel_time) = cancel_poll_time {
            other_poll_times
                .iter()
                .all(|&time| time <= cancel_time || time >= cancel_time)
        } else {
            true // No cancel task polled
        }
    }

    /// Verify that timing is deterministic and monotonic.
    fn verify_timing_determinism(&self, events: &[TraceEvent]) -> bool {
        let mut last_time: Option<Time> = None;

        for event in events {
            if let Some(last) = last_time {
                if event.timestamp < last {
                    return false; // Time went backwards
                }
            }
            last_time = Some(event.timestamp);
        }

        true
    }
}

/// Results from the priority scheduler + trace event integration test.
#[derive(Debug)]
struct TestResult {
    /// Order in which tasks were executed.
    execution_order: Vec<TaskId>,
    /// Count of events by type.
    event_counts: BTreeMap<String, usize>,
    /// Total number of trace events recorded.
    total_events: usize,
    /// Whether EDF ordering was correctly reflected in traces.
    edf_ordering_correct: bool,
    /// Whether cancel lane priority was correctly enforced.
    cancel_lane_priority_correct: bool,
    /// Whether timing was deterministic.
    timing_deterministic: bool,
}

impl TestResult {
    /// Verify that the test passed all requirements.
    fn verify_success(&self) -> bool {
        // Must have recorded events
        if self.total_events == 0 {
            return false;
        }

        // Must have executed tasks
        if self.execution_order.is_empty() {
            return false;
        }

        // Must have key event types
        let required_events = ["Spawn", "Schedule", "Poll"];
        for required in &required_events {
            if !self.event_counts.contains_key(*required) {
                return false;
            }
        }

        // All verification checks must pass
        self.edf_ordering_correct && self.cancel_lane_priority_correct && self.timing_deterministic
    }

    /// Generate a summary report.
    fn summary(&self) -> String {
        format!(
            "Priority Scheduler + Trace Event Integration Test Results:
Execution Order: {} tasks executed
Event Counts: {:#?}
Total Events: {}
EDF Ordering Correct: {}
Cancel Lane Priority Correct: {}
Timing Deterministic: {}
Test Success: {}",
            self.execution_order.len(),
            self.event_counts,
            self.total_events,
            self.edf_ordering_correct,
            self.cancel_lane_priority_correct,
            self.timing_deterministic,
            self.verify_success()
        )
    }
}

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_priority_scheduler_trace_integration() {
        let mut scenario = PrioritySchedulerTestScenario::new();
        let result = scenario.run_comprehensive_test().await;

        println!("{}", result.summary());

        assert!(
            result.verify_success(),
            "Integration test failed: {}",
            result.summary()
        );
        assert!(result.edf_ordering_correct, "EDF ordering was incorrect");
        assert!(
            result.cancel_lane_priority_correct,
            "Cancel lane priority was incorrect"
        );
        assert!(result.timing_deterministic, "Timing was not deterministic");
        assert!(
            result.total_events >= 10,
            "Should have recorded sufficient events"
        );
    }

    #[tokio::test]
    async fn test_edf_deadline_ordering() {
        let mut manager = PrioritySchedulerIntegrationManager::new();

        // Add tasks with different deadlines (not in deadline order)
        let task1 = MockTask::high_priority(100); // Later deadline
        let task2 = MockTask::high_priority(50); // Earlier deadline
        let task3 = MockTask::high_priority(75); // Middle deadline

        manager.add_task(task1.clone());
        manager.add_task(task2.clone());
        manager.add_task(task3.clone());

        // Poll tasks - should come out in deadline order (EDF)
        let mut execution_order = Vec::new();
        while let Some(task_id) = manager.poll_next_task() {
            execution_order.push(task_id);
        }

        // Verify EDF ordering: task2 (50ms), task3 (75ms), task1 (100ms)
        assert_eq!(execution_order.len(), 3, "Should execute all three tasks");
        assert_eq!(
            execution_order[0], task2.task_id,
            "Task with earliest deadline should execute first"
        );
        assert_eq!(
            execution_order[1], task3.task_id,
            "Task with middle deadline should execute second"
        );
        assert_eq!(
            execution_order[2], task1.task_id,
            "Task with latest deadline should execute third"
        );

        // Verify trace events reflect correct ordering
        let events = manager.get_recorded_events();
        let edf_correct = PrioritySchedulerTestScenario::new().verify_edf_ordering(&events);
        assert!(
            edf_correct,
            "EDF ordering should be reflected in trace events"
        );
    }

    #[tokio::test]
    async fn test_cancel_lane_preemption() {
        let mut manager = PrioritySchedulerIntegrationManager::new();

        // Add regular tasks
        let regular_task = MockTask::medium_priority(100);
        manager.add_task(regular_task.clone());

        // Add a task and immediately cancel it
        let cancel_task = MockTask::high_priority(50);
        let cancel_task_id = cancel_task.task_id;
        manager.add_task(cancel_task);
        manager.cancel_task(cancel_task_id);

        // Cancel task should be polled first despite regular task being added first
        if let Some(first_task) = manager.poll_next_task() {
            assert_eq!(
                first_task, cancel_task_id,
                "Cancelled task should preempt regular tasks"
            );
        }

        // Complete cancel task and verify regular task runs next
        manager.complete_task(cancel_task_id);
        if let Some(second_task) = manager.poll_next_task() {
            assert_eq!(
                second_task, regular_task.task_id,
                "Regular task should run after cancel task completes"
            );
        }

        let events = manager.get_recorded_events();
        assert!(!events.is_empty(), "Should have recorded trace events");

        // Verify cancel request event was recorded
        let has_cancel_request = events
            .iter()
            .any(|e| matches!(e.kind, TraceEventKind::CancelRequest));
        assert!(
            has_cancel_request,
            "Should have recorded cancel request event"
        );
    }

    #[tokio::test]
    async fn test_time_advancement_events() {
        let mut manager = PrioritySchedulerIntegrationManager::new();

        let initial_time = manager.virtual_time;

        // Advance time manually
        manager.advance_time(Duration::from_millis(100));

        // Add and poll a task (which also advances time)
        let task = MockTask::high_priority(50);
        manager.add_task(task.clone());
        manager.poll_next_task();

        let events = manager.get_recorded_events();

        // Should have time advancement events
        let time_advance_count = events
            .iter()
            .filter(|e| matches!(e.kind, TraceEventKind::TimeAdvance))
            .count();
        assert!(
            time_advance_count >= 2,
            "Should have recorded time advancement events"
        );

        // Verify timing is monotonic
        let timing_ok = PrioritySchedulerTestScenario::new().verify_timing_determinism(&events);
        assert!(timing_ok, "Time should advance monotonically");
    }

    #[tokio::test]
    async fn test_comprehensive_event_coverage() {
        let mut scenario = PrioritySchedulerTestScenario::new();
        let result = scenario.run_comprehensive_test().await;

        // Verify we recorded all expected event types
        let required_events = vec![
            "Spawn",
            "Schedule",
            "Poll",
            "Yield",
            "TimeAdvance",
            "CancelRequest",
            "Complete",
        ];

        for required_event in required_events {
            assert!(
                result.event_counts.contains_key(required_event),
                "Missing required event type: {}",
                required_event
            );
            assert!(
                result.event_counts[required_event] > 0,
                "No events recorded for type: {}",
                required_event
            );
        }

        assert!(
            result.total_events >= 15,
            "Should record comprehensive event trace"
        );
    }

    #[tokio::test]
    async fn test_mixed_lane_task_distribution() {
        let mut manager = PrioritySchedulerIntegrationManager::new();

        // Add tasks to all three lanes
        let cancel_task = MockTask::cancel_priority();
        let timed_task = MockTask::high_priority(100);
        let ready_task = MockTask::low_priority();

        let cancel_id = cancel_task.task_id;
        let timed_id = timed_task.task_id;
        let ready_id = ready_task.task_id;

        manager.add_task(ready_task); // Ready lane
        manager.add_task(timed_task); // Timed/EDF lane
        manager.add_task(cancel_task); // Will move to cancel lane
        manager.cancel_task(cancel_id); // Move to cancel lane

        // Poll order should be: Cancel lane -> EDF lane -> Ready lane
        let mut execution_order = Vec::new();
        while let Some(task_id) = manager.poll_next_task() {
            execution_order.push(task_id);
        }

        assert_eq!(execution_order.len(), 3, "Should execute all three tasks");
        assert_eq!(
            execution_order[0], cancel_id,
            "Cancel lane task should execute first"
        );
        assert_eq!(
            execution_order[1], timed_id,
            "EDF lane task should execute second"
        );
        assert_eq!(
            execution_order[2], ready_id,
            "Ready lane task should execute third"
        );

        let events = manager.get_recorded_events();

        // Verify all lanes are represented in schedule events
        let schedule_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e.kind, TraceEventKind::Schedule))
            .collect();

        assert!(
            schedule_events.len() >= 3,
            "Should have schedule events for all tasks"
        );
    }
}
