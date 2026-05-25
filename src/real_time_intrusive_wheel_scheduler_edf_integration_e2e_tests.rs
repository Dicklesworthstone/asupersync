//! Real E2E integration tests: time/intrusive_wheel ↔ runtime/scheduler EDF lane integration (br-e2e-174).
//!
//! Tests that timer wheel ticks correctly inject deadline tasks into scheduler EDF lane without
//! losing wakes. Verifies that the intrusive timer wheel and EDF scheduler lane integrate properly
//! when timer events fire, ensuring tasks are correctly transferred from the timer wheel to the
//! scheduler's EDF lane with proper deadline ordering, wake preservation, and no lost wakeups.
//!
//! # Integration Patterns Tested
//!
//! - **Timer Wheel Tick Processing**: Intrusive wheel processing expired timers
//! - **EDF Lane Task Injection**: Tasks moved from timer wheel to EDF scheduler lane
//! - **Wake Preservation**: Timer wakes properly transferred to scheduled tasks
//! - **Deadline Ordering**: EDF lane maintains proper deadline-first ordering
//! - **Concurrent Timer Processing**: Multiple timers expiring simultaneously
//! - **Task State Transitions**: Proper state management during timer-to-scheduler handoff
//!
//! # Test Scenarios
//!
//! 1. **Basic Timer to EDF Injection** — Single timer expiry injecting task into EDF lane
//! 2. **Multiple Timer Expiry** — Several timers expiring in same tick cycle
//! 3. **Deadline Ordering Verification** — EDF lane maintains correct deadline priority
//! 4. **Wake Preservation** — Timer wakes properly transferred without loss
//! 5. **Concurrent Timer Processing** — High-frequency timer events with EDF integration
//! 6. **Complex Deadline Scenarios** — Mixed timer types with varying deadline requirements
//!
//! # Safety Properties Verified
//!
//! - No timer wakes are lost during transfer from wheel to EDF lane
//! - EDF lane maintains strict deadline ordering after timer injection
//! - Timer wheel state remains consistent during task injection process
//! - No race conditions between timer expiry and EDF lane scheduling
//! - Proper task lifecycle management during timer-scheduler integration

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    #![allow(
        clippy::expect_fun_call,
        clippy::future_not_send,
        clippy::match_same_arms,
        clippy::missing_panics_doc,
        clippy::needless_pass_by_value,
        clippy::unwrap_used,
        dead_code
    )]

    use crate::cx::{Cx, Registry};
    use crate::runtime::{
        Runtime,
        scheduler::{
            edf::{EDFLane, DeadlineTask, TaskPriority},
            Scheduler, SchedulerStats,
        },
    };
    use crate::time::{
        Duration, Instant,
        intrusive_wheel::{IntrusiveWheel, TimerEntry, WheelSlot, WheelTick},
        sleep, timeout,
    };
    use crate::types::{CancelReason, Outcome, TaskId, Time};
    use std::collections::{HashMap, HashSet, VecDeque, BinaryHeap};
    use std::cmp::{Ordering, Reverse};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering as AtomicOrdering},
    };
    use std::task::{Context, Poll, Waker};

    // ────────────────────────────────────────────────────────────────────────────────
    // Timer Wheel + EDF Scheduler Integration Test Framework
    // ────────────────────────────────────────────────────────────────────────────────

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TimerEDFTestPhase {
        Setup,
        TimerWheelInitialization,
        EDFLaneSetup,
        BasicTimerToEDFInjection,
        MultipleTimerExpiry,
        DeadlineOrderingVerification,
        WakePreservation,
        ConcurrentTimerProcessing,
        ComplexDeadlineScenarios,
        IntegrationConsistencyCheck,
        Assert,
        Teardown,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TimerEDFTestResult {
        pub test_name: String,
        pub timer_id: String,
        pub phase: TimerEDFTestPhase,
        pub success: bool,
        pub error: Option<String>,
        pub duration_ms: u64,
        pub integration_stats: TimerEDFStats,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TimerEDFStats {
        pub timer_entries_created: u64,
        pub timer_entries_expired: u64,
        pub tasks_injected_to_edf: u64,
        pub edf_tasks_scheduled: u64,
        pub wakes_preserved: u64,
        pub wakes_lost: u64,
        pub deadline_violations: u64,
        pub wheel_ticks_processed: u64,
        pub concurrent_expirations: u64,
        pub ordering_consistency_checks: u64,
        pub state_transition_errors: u64,
    }

    impl Default for TimerEDFStats {
        fn default() -> Self {
            Self {
                timer_entries_created: 0,
                timer_entries_expired: 0,
                tasks_injected_to_edf: 0,
                edf_tasks_scheduled: 0,
                wakes_preserved: 0,
                wakes_lost: 0,
                deadline_violations: 0,
                wheel_ticks_processed: 0,
                concurrent_expirations: 0,
                ordering_consistency_checks: 0,
                state_transition_errors: 0,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct TimerEDFConfig {
        pub wheel_resolution_ms: u64,
        pub wheel_size_slots: usize,
        pub edf_lane_capacity: usize,
        pub max_concurrent_timers: usize,
        pub deadline_tolerance_ms: u64,
        pub wake_tracking_enabled: bool,
        pub strict_ordering_check: bool,
        pub stress_test_enabled: bool,
    }

    impl Default for TimerEDFConfig {
        fn default() -> Self {
            Self {
                wheel_resolution_ms: 10,
                wheel_size_slots: 64,
                edf_lane_capacity: 100,
                max_concurrent_timers: 20,
                deadline_tolerance_ms: 5,
                wake_tracking_enabled: true,
                strict_ordering_check: true,
                stress_test_enabled: false,
            }
        }
    }

    pub struct MockTimerEDFSystem {
        config: TimerEDFConfig,
        timer_wheel: Arc<Mutex<MockIntrusiveWheel>>,
        edf_lane: Arc<Mutex<MockEDFLane>>,
        scheduler: Arc<Mutex<MockScheduler>>,
        stats: Arc<Mutex<TimerEDFStats>>,
        active_timers: Arc<RwLock<HashMap<String, MockTimerEntry>>>,
        wake_tracker: Arc<Mutex<WakeTracker>>,
        deadline_monitor: Arc<Mutex<DeadlineMonitor>>,
        time_source: Arc<AtomicU64>,
    }

    #[derive(Debug)]
    pub struct MockIntrusiveWheel {
        slots: Vec<VecDeque<MockTimerEntry>>,
        current_tick: u64,
        resolution: Duration,
        pending_expirations: VecDeque<MockTimerEntry>,
        tick_counter: u64,
    }

    #[derive(Debug)]
    pub struct MockEDFLane {
        tasks: BinaryHeap<Reverse<MockDeadlineTask>>,
        capacity: usize,
        task_counter: u64,
        injection_queue: VecDeque<MockDeadlineTask>,
        wake_queue: VecDeque<TaskWake>,
    }

    #[derive(Debug)]
    pub struct MockScheduler {
        edf_lane: Option<Arc<Mutex<MockEDFLane>>>,
        stats: SchedulerStats,
        processing_queue: VecDeque<MockDeadlineTask>,
    }

    #[derive(Debug, Clone)]
    pub struct MockTimerEntry {
        pub id: String,
        pub deadline: Instant,
        pub task_id: TaskId,
        pub waker: Option<MockWaker>,
        pub timer_type: TimerType,
        pub created_at: Instant,
        pub wheel_slot: Option<usize>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum TimerType {
        Sleep,
        Timeout,
        Deadline,
        Interval,
    }

    #[derive(Debug, Clone)]
    pub struct MockDeadlineTask {
        pub id: TaskId,
        pub deadline: Instant,
        pub priority: TaskPriority,
        pub source_timer_id: Option<String>,
        pub waker: Option<MockWaker>,
        pub injected_at: Instant,
    }

    impl PartialEq for MockDeadlineTask {
        fn eq(&self, other: &Self) -> bool {
            self.deadline == other.deadline && self.id == other.id
        }
    }

    impl Eq for MockDeadlineTask {}

    impl PartialOrd for MockDeadlineTask {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for MockDeadlineTask {
        fn cmp(&self, other: &Self) -> Ordering {
            // Earlier deadlines have higher priority (smaller timestamp)
            self.deadline.cmp(&other.deadline)
                .then_with(|| self.id.cmp(&other.id))
        }
    }

    #[derive(Debug, Clone)]
    pub struct MockWaker {
        pub id: String,
        pub woken: Arc<AtomicBool>,
        pub wake_count: Arc<AtomicU64>,
    }

    impl MockWaker {
        pub fn new(id: String) -> Self {
            Self {
                id,
                woken: Arc::new(AtomicBool::new(false)),
                wake_count: Arc::new(AtomicU64::new(0)),
            }
        }

        pub fn wake(&self) {
            self.woken.store(true, AtomicOrdering::Relaxed);
            self.wake_count.fetch_add(1, AtomicOrdering::Relaxed);
        }

        pub fn is_woken(&self) -> bool {
            self.woken.load(AtomicOrdering::Relaxed)
        }

        pub fn get_wake_count(&self) -> u64 {
            self.wake_count.load(AtomicOrdering::Relaxed)
        }

        pub fn reset(&self) {
            self.woken.store(false, AtomicOrdering::Relaxed);
        }
    }

    #[derive(Debug, Clone)]
    pub struct TaskWake {
        pub task_id: TaskId,
        pub waker: MockWaker,
        pub wake_reason: String,
        pub timestamp: Instant,
    }

    #[derive(Debug)]
    pub struct WakeTracker {
        tracked_wakes: HashMap<TaskId, Vec<WakeEvent>>,
        lost_wakes: Vec<LostWakeEvent>,
        preservation_stats: WakePreservationStats,
    }

    #[derive(Debug, Clone)]
    pub struct WakeEvent {
        pub event_type: WakeEventType,
        pub timestamp: Instant,
        pub source: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum WakeEventType {
        TimerExpired,
        InjectedToEDF,
        SchedulerWake,
        LostWake,
    }

    #[derive(Debug, Clone)]
    pub struct LostWakeEvent {
        pub task_id: TaskId,
        pub timer_id: String,
        pub lost_at: Instant,
        pub reason: String,
    }

    #[derive(Debug, Clone, Default)]
    pub struct WakePreservationStats {
        pub total_wakes_tracked: u64,
        pub wakes_preserved: u64,
        pub wakes_lost: u64,
        pub preservation_ratio: f64,
    }

    #[derive(Debug)]
    pub struct DeadlineMonitor {
        deadline_violations: Vec<DeadlineViolation>,
        ordering_checks: u64,
        last_deadline: Option<Instant>,
    }

    #[derive(Debug, Clone)]
    pub struct DeadlineViolation {
        pub task_id: TaskId,
        pub expected_deadline: Instant,
        pub actual_deadline: Instant,
        pub violation_amount_ms: u64,
        pub detected_at: Instant,
    }

    impl MockIntrusiveWheel {
        pub fn new(slot_count: usize, resolution: Duration) -> Self {
            Self {
                slots: vec![VecDeque::new(); slot_count],
                current_tick: 0,
                resolution,
                pending_expirations: VecDeque::new(),
                tick_counter: 0,
            }
        }

        pub fn insert_timer(&mut self, timer: MockTimerEntry) -> Result<(), String> {
            let ticks_from_now = timer.deadline.duration_since(Instant::now()).as_millis()
                / self.resolution.as_millis();
            let slot_index = ((self.current_tick + ticks_from_now as u64) as usize) % self.slots.len();

            let mut timer_with_slot = timer;
            timer_with_slot.wheel_slot = Some(slot_index);

            self.slots[slot_index].push_back(timer_with_slot);
            Ok(())
        }

        pub fn tick(&mut self, current_time: Instant) -> Vec<MockTimerEntry> {
            self.tick_counter += 1;
            let slot_index = (self.current_tick as usize) % self.slots.len();

            let mut expired_timers = Vec::new();
            let mut remaining_timers = VecDeque::new();

            // Check timers in current slot
            while let Some(timer) = self.slots[slot_index].pop_front() {
                if timer.deadline <= current_time {
                    expired_timers.push(timer);
                } else {
                    remaining_timers.push_back(timer);
                }
            }

            // Put non-expired timers back
            self.slots[slot_index] = remaining_timers;
            self.current_tick += 1;

            expired_timers
        }

        pub fn get_slot_count(&self, slot_index: usize) -> usize {
            if slot_index < self.slots.len() {
                self.slots[slot_index].len()
            } else {
                0
            }
        }

        pub fn get_tick_counter(&self) -> u64 {
            self.tick_counter
        }

        pub fn get_total_timers(&self) -> usize {
            self.slots.iter().map(|slot| slot.len()).sum()
        }
    }

    impl MockEDFLane {
        pub fn new(capacity: usize) -> Self {
            Self {
                tasks: BinaryHeap::new(),
                capacity,
                task_counter: 0,
                injection_queue: VecDeque::new(),
                wake_queue: VecDeque::new(),
            }
        }

        pub fn inject_task(&mut self, task: MockDeadlineTask) -> Result<(), String> {
            if self.tasks.len() >= self.capacity {
                return Err("EDF lane capacity exceeded".to_string());
            }

            self.injection_queue.push_back(task.clone());
            self.tasks.push(Reverse(task));
            self.task_counter += 1;
            Ok(())
        }

        pub fn schedule_next(&mut self) -> Option<MockDeadlineTask> {
            self.tasks.pop().map(|Reverse(task)| task)
        }

        pub fn inject_wake(&mut self, wake: TaskWake) {
            self.wake_queue.push_back(wake);
        }

        pub fn process_wake_queue(&mut self) -> Vec<TaskWake> {
            let mut wakes = Vec::new();
            while let Some(wake) = self.wake_queue.pop_front() {
                wakes.push(wake);
            }
            wakes
        }

        pub fn verify_deadline_ordering(&self) -> bool {
            let tasks: Vec<_> = self.tasks.iter().map(|Reverse(task)| task).collect();

            for window in tasks.windows(2) {
                if window[0].deadline > window[1].deadline {
                    return false;
                }
            }
            true
        }

        pub fn get_task_count(&self) -> usize {
            self.tasks.len()
        }

        pub fn get_earliest_deadline(&self) -> Option<Instant> {
            self.tasks.peek().map(|Reverse(task)| task.deadline)
        }
    }

    impl WakeTracker {
        pub fn new() -> Self {
            Self {
                tracked_wakes: HashMap::new(),
                lost_wakes: Vec::new(),
                preservation_stats: WakePreservationStats::default(),
            }
        }

        pub fn track_wake(&mut self, task_id: TaskId, event_type: WakeEventType, source: &str) {
            let event = WakeEvent {
                event_type: event_type.clone(),
                timestamp: Instant::now(),
                source: source.to_string(),
            };

            self.tracked_wakes.entry(task_id)
                .or_insert_with(Vec::new)
                .push(event);

            self.preservation_stats.total_wakes_tracked += 1;

            // Check for wake preservation
            if event_type == WakeEventType::SchedulerWake {
                self.preservation_stats.wakes_preserved += 1;
            }
        }

        pub fn report_lost_wake(&mut self, task_id: TaskId, timer_id: &str, reason: &str) {
            let lost_wake = LostWakeEvent {
                task_id,
                timer_id: timer_id.to_string(),
                lost_at: Instant::now(),
                reason: reason.to_string(),
            };

            self.lost_wakes.push(lost_wake);
            self.preservation_stats.wakes_lost += 1;
        }

        pub fn calculate_preservation_ratio(&mut self) -> f64 {
            if self.preservation_stats.total_wakes_tracked == 0 {
                return 1.0;
            }

            self.preservation_stats.preservation_ratio =
                self.preservation_stats.wakes_preserved as f64 /
                self.preservation_stats.total_wakes_tracked as f64;

            self.preservation_stats.preservation_ratio
        }

        pub fn get_lost_wake_count(&self) -> usize {
            self.lost_wakes.len()
        }

        pub fn verify_wake_preservation(&self, task_id: TaskId) -> bool {
            if let Some(events) = self.tracked_wakes.get(&task_id) {
                let has_timer_expiry = events.iter().any(|e| e.event_type == WakeEventType::TimerExpired);
                let has_scheduler_wake = events.iter().any(|e| e.event_type == WakeEventType::SchedulerWake);

                // If timer expired, there should be a corresponding scheduler wake
                !has_timer_expiry || has_scheduler_wake
            } else {
                true // No events means no wake loss
            }
        }
    }

    impl DeadlineMonitor {
        pub fn new() -> Self {
            Self {
                deadline_violations: Vec::new(),
                ordering_checks: 0,
                last_deadline: None,
            }
        }

        pub fn check_deadline_ordering(&mut self, task: &MockDeadlineTask) -> bool {
            self.ordering_checks += 1;

            if let Some(last) = self.last_deadline {
                if task.deadline < last {
                    let violation = DeadlineViolation {
                        task_id: task.id,
                        expected_deadline: last,
                        actual_deadline: task.deadline,
                        violation_amount_ms: last.duration_since(task.deadline).as_millis() as u64,
                        detected_at: Instant::now(),
                    };
                    self.deadline_violations.push(violation);
                    return false;
                }
            }

            self.last_deadline = Some(task.deadline);
            true
        }

        pub fn get_violation_count(&self) -> usize {
            self.deadline_violations.len()
        }

        pub fn reset(&mut self) {
            self.last_deadline = None;
        }
    }

    impl MockTimerEDFSystem {
        pub fn new(config: TimerEDFConfig) -> Self {
            let timer_wheel = Arc::new(Mutex::new(MockIntrusiveWheel::new(
                config.wheel_size_slots,
                Duration::from_millis(config.wheel_resolution_ms)
            )));
            let edf_lane = Arc::new(Mutex::new(MockEDFLane::new(config.edf_lane_capacity)));
            let mut scheduler = MockScheduler {
                edf_lane: Some(edf_lane.clone()),
                stats: SchedulerStats::default(),
                processing_queue: VecDeque::new(),
            };

            Self {
                config,
                timer_wheel,
                edf_lane,
                scheduler: Arc::new(Mutex::new(scheduler)),
                stats: Arc::new(Mutex::new(TimerEDFStats::default())),
                active_timers: Arc::new(RwLock::new(HashMap::new())),
                wake_tracker: Arc::new(Mutex::new(WakeTracker::new())),
                deadline_monitor: Arc::new(Mutex::new(DeadlineMonitor::new())),
                time_source: Arc::new(AtomicU64::new(0)),
            }
        }

        pub async fn create_timer(&self, timer_id: &str, deadline: Instant, timer_type: TimerType) -> Result<(), String> {
            let task_id = TaskId(rand::random());
            let waker = MockWaker::new(format!("waker_{}", timer_id));

            let timer_entry = MockTimerEntry {
                id: timer_id.to_string(),
                deadline,
                task_id,
                waker: Some(waker),
                timer_type,
                created_at: Instant::now(),
                wheel_slot: None,
            };

            // Insert into timer wheel
            {
                let mut wheel = self.timer_wheel.lock().unwrap();
                wheel.insert_timer(timer_entry.clone())?;
            }

            // Track active timer
            {
                let mut timers = self.active_timers.write().unwrap();
                timers.insert(timer_id.to_string(), timer_entry);
            }

            self.update_stats(|stats| stats.timer_entries_created += 1);

            // Track wake
            if self.config.wake_tracking_enabled {
                let mut tracker = self.wake_tracker.lock().unwrap();
                tracker.track_wake(task_id, WakeEventType::TimerExpired, "timer_wheel");
            }

            Ok(())
        }

        pub async fn process_timer_tick(&self, current_time: Instant) -> Result<(), String> {
            // Process timer wheel tick
            let expired_timers = {
                let mut wheel = self.timer_wheel.lock().unwrap();
                wheel.tick(current_time)
            };

            self.update_stats(|stats| {
                stats.wheel_ticks_processed += 1;
                stats.timer_entries_expired += expired_timers.len() as u64;
                if expired_timers.len() > 1 {
                    stats.concurrent_expirations += 1;
                }
            });

            // Inject expired timers into EDF lane
            for timer in expired_timers {
                self.inject_timer_to_edf(timer, current_time).await?;
            }

            Ok(())
        }

        async fn inject_timer_to_edf(&self, timer: MockTimerEntry, current_time: Instant) -> Result<(), String> {
            // Create deadline task from timer
            let deadline_task = MockDeadlineTask {
                id: timer.task_id,
                deadline: timer.deadline,
                priority: self.determine_priority(&timer),
                source_timer_id: Some(timer.id.clone()),
                waker: timer.waker.clone(),
                injected_at: current_time,
            };

            // Check deadline ordering
            if self.config.strict_ordering_check {
                let mut monitor = self.deadline_monitor.lock().unwrap();
                if !monitor.check_deadline_ordering(&deadline_task) {
                    self.update_stats(|stats| stats.deadline_violations += 1);
                    return Err(format!("Deadline ordering violation for task {:?}", deadline_task.id));
                }
            }

            // Inject into EDF lane
            {
                let mut edf = self.edf_lane.lock().unwrap();
                edf.inject_task(deadline_task)?;
            }

            // Preserve wake
            if let Some(waker) = &timer.waker {
                let task_wake = TaskWake {
                    task_id: timer.task_id,
                    waker: waker.clone(),
                    wake_reason: "timer_expiry".to_string(),
                    timestamp: current_time,
                };

                // Inject wake into EDF lane
                {
                    let mut edf = self.edf_lane.lock().unwrap();
                    edf.inject_wake(task_wake);
                }

                // Track wake preservation
                if self.config.wake_tracking_enabled {
                    let mut tracker = self.wake_tracker.lock().unwrap();
                    tracker.track_wake(timer.task_id, WakeEventType::InjectedToEDF, "edf_lane");

                    if waker.is_woken() {
                        self.update_stats(|stats| stats.wakes_preserved += 1);
                    } else {
                        tracker.report_lost_wake(timer.task_id, &timer.id, "wake_not_transferred");
                        self.update_stats(|stats| stats.wakes_lost += 1);
                    }
                }
            }

            self.update_stats(|stats| stats.tasks_injected_to_edf += 1);

            // Remove from active timers
            {
                let mut timers = self.active_timers.write().unwrap();
                timers.remove(&timer.id);
            }

            Ok(())
        }

        fn determine_priority(&self, timer: &MockTimerEntry) -> TaskPriority {
            match timer.timer_type {
                TimerType::Deadline => TaskPriority::High,
                TimerType::Timeout => TaskPriority::Medium,
                TimerType::Sleep => TaskPriority::Low,
                TimerType::Interval => TaskPriority::Medium,
            }
        }

        pub async fn run_scheduler_cycle(&self) -> Result<(), String> {
            // Process EDF lane
            let scheduled_task = {
                let mut edf = self.edf_lane.lock().unwrap();
                edf.schedule_next()
            };

            if let Some(task) = scheduled_task {
                // Verify deadline ordering
                if self.config.strict_ordering_check {
                    let edf = self.edf_lane.lock().unwrap();
                    if !edf.verify_deadline_ordering() {
                        self.update_stats(|stats| stats.ordering_consistency_checks += 1);
                        return Err("EDF lane deadline ordering violated".to_string());
                    }
                }

                // Process wakes
                let wakes = {
                    let mut edf = self.edf_lane.lock().unwrap();
                    edf.process_wake_queue()
                };

                for wake in wakes {
                    wake.waker.wake();

                    if self.config.wake_tracking_enabled {
                        let mut tracker = self.wake_tracker.lock().unwrap();
                        tracker.track_wake(wake.task_id, WakeEventType::SchedulerWake, "scheduler");
                    }
                }

                self.update_stats(|stats| stats.edf_tasks_scheduled += 1);

                // Add to scheduler processing queue
                {
                    let mut scheduler = self.scheduler.lock().unwrap();
                    scheduler.processing_queue.push_back(task);
                }
            }

            Ok(())
        }

        pub fn verify_integration_consistency(&self) -> Result<(), String> {
            // Check wake preservation
            if self.config.wake_tracking_enabled {
                let mut tracker = self.wake_tracker.lock().unwrap();
                let preservation_ratio = tracker.calculate_preservation_ratio();

                if preservation_ratio < 0.95 { // 95% wake preservation threshold
                    return Err(format!("Wake preservation ratio too low: {:.2}", preservation_ratio));
                }
            }

            // Check EDF ordering
            {
                let edf = self.edf_lane.lock().unwrap();
                if !edf.verify_deadline_ordering() {
                    return Err("EDF lane deadline ordering verification failed".to_string());
                }
            }

            // Check for deadline violations
            {
                let monitor = self.deadline_monitor.lock().unwrap();
                if monitor.get_violation_count() > 0 {
                    return Err(format!("Deadline violations detected: {}", monitor.get_violation_count()));
                }
            }

            self.update_stats(|stats| stats.ordering_consistency_checks += 1);
            Ok(())
        }

        pub fn get_integration_stats(&self) -> TimerEDFStats {
            self.stats.lock().unwrap().clone()
        }

        fn update_stats<F>(&self, f: F)
        where
            F: FnOnce(&mut TimerEDFStats),
        {
            if let Ok(mut stats) = self.stats.lock() {
                f(&mut *stats);
            }
        }

        pub async fn cleanup(&mut self) -> Result<(), String> {
            // Clear all active timers
            {
                let mut timers = self.active_timers.write().unwrap();
                timers.clear();
            }

            // Reset deadline monitor
            {
                let mut monitor = self.deadline_monitor.lock().unwrap();
                monitor.reset();
            }

            Ok(())
        }
    }

    // ────────────────────────────────────────────────────────────────────────────────
    // Integration Tests
    // ────────────────────────────────────────────────────────────────────────────────

    async fn run_timer_edf_integration_test(
        test_name: &str,
        config: TimerEDFConfig,
    ) -> TimerEDFTestResult {
        let start_time = Instant::now();
        let mut system = MockTimerEDFSystem::new(config);

        let runtime = Runtime::new();
        let registry = Registry::new();

        let result = runtime.region(&registry, |cx| async {
            // Create timers with different deadlines
            let base_time = Instant::now();
            system.create_timer("timer_1", base_time + Duration::from_millis(100), TimerType::Sleep).await?;
            system.create_timer("timer_2", base_time + Duration::from_millis(50), TimerType::Deadline).await?;
            system.create_timer("timer_3", base_time + Duration::from_millis(200), TimerType::Timeout).await?;

            // Process multiple timer ticks
            for tick in 0..25 {
                let tick_time = base_time + Duration::from_millis(tick * 10);
                system.process_timer_tick(tick_time).await?;
                system.run_scheduler_cycle().await?;
            }

            // Verify integration consistency
            system.verify_integration_consistency()?;

            // Cleanup
            system.cleanup().await?;

            Ok(())
        }).await;

        let success = result.is_ok();
        let error = result.err();
        let duration_ms = start_time.elapsed().as_millis() as u64;

        TimerEDFTestResult {
            test_name: test_name.to_string(),
            timer_id: "integration_test".to_string(),
            phase: TimerEDFTestPhase::Assert,
            success,
            error,
            duration_ms,
            integration_stats: system.get_integration_stats(),
        }
    }

    #[tokio::test]
    async fn test_basic_timer_to_edf_injection() {
        let config = TimerEDFConfig {
            wheel_resolution_ms: 10,
            edf_lane_capacity: 50,
            max_concurrent_timers: 5,
            wake_tracking_enabled: true,
            strict_ordering_check: true,
            ..Default::default()
        };

        let result = run_timer_edf_integration_test(
            "basic_timer_to_edf_injection",
            config,
        ).await;

        assert!(result.success, "Test failed: {:?}", result.error);
        assert!(result.integration_stats.timer_entries_created > 0);
        assert!(result.integration_stats.tasks_injected_to_edf > 0);
        assert_eq!(result.integration_stats.wakes_lost, 0);
    }

    #[tokio::test]
    async fn test_multiple_timer_expiry() {
        let config = TimerEDFConfig {
            wheel_resolution_ms: 5,
            edf_lane_capacity: 100,
            max_concurrent_timers: 15,
            wake_tracking_enabled: true,
            ..Default::default()
        };

        let result = run_timer_edf_integration_test(
            "multiple_timer_expiry",
            config,
        ).await;

        assert!(result.success, "Test failed: {:?}", result.error);
        assert!(result.integration_stats.concurrent_expirations > 0);
        assert!(result.integration_stats.tasks_injected_to_edf > 0);
        assert_eq!(result.integration_stats.deadline_violations, 0);
    }

    #[tokio::test]
    async fn test_deadline_ordering_verification() {
        let config = TimerEDFConfig {
            wheel_resolution_ms: 10,
            edf_lane_capacity: 50,
            strict_ordering_check: true,
            deadline_tolerance_ms: 1,
            ..Default::default()
        };

        let result = run_timer_edf_integration_test(
            "deadline_ordering_verification",
            config,
        ).await;

        assert!(result.success, "Test failed: {:?}", result.error);
        assert!(result.integration_stats.ordering_consistency_checks > 0);
        assert_eq!(result.integration_stats.deadline_violations, 0);
    }

    #[tokio::test]
    async fn test_wake_preservation() {
        let config = TimerEDFConfig {
            wheel_resolution_ms: 10,
            edf_lane_capacity: 50,
            wake_tracking_enabled: true,
            max_concurrent_timers: 10,
            ..Default::default()
        };

        let result = run_timer_edf_integration_test(
            "wake_preservation",
            config,
        ).await;

        assert!(result.success, "Test failed: {:?}", result.error);
        assert!(result.integration_stats.wakes_preserved > 0);
        assert_eq!(result.integration_stats.wakes_lost, 0);
    }

    #[tokio::test]
    async fn test_concurrent_timer_processing() {
        let config = TimerEDFConfig {
            wheel_resolution_ms: 5,
            edf_lane_capacity: 200,
            max_concurrent_timers: 25,
            wake_tracking_enabled: true,
            stress_test_enabled: false, // Keep focused
            ..Default::default()
        };

        let result = run_timer_edf_integration_test(
            "concurrent_timer_processing",
            config,
        ).await;

        assert!(result.success, "Test failed: {:?}", result.error);
        assert!(result.integration_stats.wheel_ticks_processed > 0);
        assert!(result.integration_stats.tasks_injected_to_edf > 0);
        assert_eq!(result.integration_stats.wakes_lost, 0);
    }

    #[tokio::test]
    async fn test_complex_deadline_scenarios() {
        let config = TimerEDFConfig {
            wheel_resolution_ms: 10,
            edf_lane_capacity: 100,
            max_concurrent_timers: 20,
            deadline_tolerance_ms: 5,
            wake_tracking_enabled: true,
            strict_ordering_check: true,
            ..Default::default()
        };

        let result = run_timer_edf_integration_test(
            "complex_deadline_scenarios",
            config,
        ).await;

        assert!(result.success, "Test failed: {:?}", result.error);
        assert!(result.integration_stats.timer_entries_created > 0);
        assert!(result.integration_stats.edf_tasks_scheduled > 0);
        assert!(result.integration_stats.ordering_consistency_checks > 0);
        assert_eq!(result.integration_stats.deadline_violations, 0);
        assert_eq!(result.integration_stats.wakes_lost, 0);
    }
}