//! Multi-worker 3-lane scheduler with work stealing.
//!
//! This scheduler coordinates multiple worker threads while maintaining
//! strict priority ordering: cancel > timed > ready.

use crate::runtime::scheduler::global_injector::GlobalInjector;
use crate::runtime::scheduler::priority::Scheduler as PriorityScheduler;
use crate::runtime::scheduler::worker::Parker;
use crate::runtime::RuntimeState;
use crate::time::TimerDriverHandle;
use crate::tracing_compat::trace;
use crate::types::{CxInner, Outcome, TaskId, Time};
use crate::util::DetRng;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

/// Identifier for a scheduler worker.
pub type WorkerId = usize;

/// A multi-worker scheduler with 3-lane priority support.
///
/// Each worker maintains a local `PriorityScheduler` for tasks spawned within
/// that worker. Cross-thread wakeups go through the shared `GlobalInjector`.
/// Workers strictly process cancel work before timed, and timed before ready.
#[derive(Debug)]
pub struct ThreeLaneScheduler {
    /// Global injection queue for cross-thread wakeups.
    global: Arc<GlobalInjector>,
    /// Worker handles for thread spawning.
    workers: Vec<ThreeLaneWorker>,
    /// Shutdown signal.
    shutdown: Arc<AtomicBool>,
    /// Parkers for waking idle workers.
    parkers: Vec<Parker>,
    /// Timer driver for processing timer wakeups.
    timer_driver: Option<TimerDriverHandle>,
}

impl ThreeLaneScheduler {
    /// Creates a new 3-lane scheduler with the given number of workers.
    pub fn new(worker_count: usize, state: &Arc<Mutex<RuntimeState>>) -> Self {
        let global = Arc::new(GlobalInjector::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut workers = Vec::with_capacity(worker_count);
        let mut parkers = Vec::with_capacity(worker_count);
        let mut local_schedulers: Vec<Arc<Mutex<PriorityScheduler>>> =
            Vec::with_capacity(worker_count);

        // Get timer driver from runtime state
        let timer_driver = state
            .lock()
            .expect("runtime state lock poisoned")
            .timer_driver_handle();

        // Create local schedulers first so we can share references for stealing
        for _ in 0..worker_count {
            local_schedulers.push(Arc::new(Mutex::new(PriorityScheduler::new())));
        }

        // Create workers with references to all other workers' schedulers
        for id in 0..worker_count {
            let parker = Parker::new();
            parkers.push(parker.clone());

            // Stealers: all other workers' local schedulers (excluding self)
            let stealers: Vec<_> = local_schedulers
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != id)
                .map(|(_, sched)| Arc::clone(sched))
                .collect();

            workers.push(ThreeLaneWorker {
                id,
                local: Arc::clone(&local_schedulers[id]),
                stealers,
                global: Arc::clone(&global),
                state: Arc::clone(state),
                parker,
                rng: DetRng::new(id as u64),
                shutdown: Arc::clone(&shutdown),
                timer_driver: timer_driver.clone(),
            });
        }

        Self {
            global,
            workers,
            shutdown,
            parkers,
            timer_driver,
        }
    }

    /// Injects a task into the cancel lane for cross-thread wakeup.
    pub fn inject_cancel(&self, task: TaskId, priority: u8) {
        self.global.inject_cancel(task, priority);
        self.wake_one();
    }

    /// Injects a task into the timed lane for cross-thread wakeup.
    pub fn inject_timed(&self, task: TaskId, deadline: Time) {
        self.global.inject_timed(task, deadline);
        self.wake_one();
    }

    /// Injects a task into the ready lane for cross-thread wakeup.
    pub fn inject_ready(&self, task: TaskId, priority: u8) {
        self.global.inject_ready(task, priority);
        self.wake_one();
    }

    /// Spawns a task (shorthand for inject_ready).
    pub fn spawn(&self, task: TaskId, priority: u8) {
        self.inject_ready(task, priority);
    }

    /// Wakes a task by injecting it into the ready lane.
    ///
    /// For cancel wakeups, use `inject_cancel` instead.
    pub fn wake(&self, task: TaskId, priority: u8) {
        self.inject_ready(task, priority);
    }

    /// Wakes one idle worker.
    fn wake_one(&self) {
        // Simple strategy: wake the first parker
        // TODO: Could be smarter (round-robin, least-loaded, etc.)
        if let Some(parker) = self.parkers.first() {
            parker.unpark();
        }
    }

    /// Wakes all idle workers.
    pub fn wake_all(&self) {
        for parker in &self.parkers {
            parker.unpark();
        }
    }

    /// Extract workers to run them in threads.
    pub fn take_workers(&mut self) -> Vec<ThreeLaneWorker> {
        std::mem::take(&mut self.workers)
    }

    /// Signals all workers to shutdown.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.wake_all();
    }

    /// Returns true if shutdown has been signaled.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }
}

/// A worker thread for the 3-lane scheduler.
#[derive(Debug)]
pub struct ThreeLaneWorker {
    /// Unique worker ID.
    pub id: WorkerId,
    /// Local 3-lane scheduler for this worker.
    pub local: Arc<Mutex<PriorityScheduler>>,
    /// References to other workers' local schedulers for stealing.
    pub stealers: Vec<Arc<Mutex<PriorityScheduler>>>,
    /// Global injection queue.
    pub global: Arc<GlobalInjector>,
    /// Shared runtime state.
    pub state: Arc<Mutex<RuntimeState>>,
    /// Parking mechanism for idle workers.
    pub parker: Parker,
    /// Deterministic RNG for stealing decisions.
    pub rng: DetRng,
    /// Shutdown signal.
    pub shutdown: Arc<AtomicBool>,
    /// Timer driver for processing timer wakeups (optional).
    pub timer_driver: Option<TimerDriverHandle>,
}

impl ThreeLaneWorker {
    /// Runs the worker scheduling loop.
    ///
    /// The loop maintains strict priority ordering:
    /// 1. Process expired timers (wakes tasks via their wakers)
    /// 2. Cancel work (global then local)
    /// 3. Timed work (global then local)
    /// 4. Ready work (global then local)
    /// 5. Steal from other workers
    /// 6. Park (with timeout based on next timer deadline)
    pub fn run_loop(&mut self) {
        const SPIN_LIMIT: u32 = 64;
        const YIELD_LIMIT: u32 = 16;

        while !self.shutdown.load(Ordering::Relaxed) {
            // PHASE 0: Process expired timers (fires wakers, which may inject tasks)
            if let Some(timer) = &self.timer_driver {
                let _ = timer.process_timers();
            }

            // PHASE 1: Cancel work (highest priority, never starve)
            if let Some(task) = self.try_cancel_work() {
                self.execute(task);
                continue;
            }

            // PHASE 2: Timed work
            if let Some(task) = self.try_timed_work() {
                self.execute(task);
                continue;
            }

            // PHASE 3: Ready work
            if let Some(task) = self.try_ready_work() {
                self.execute(task);
                continue;
            }

            // PHASE 4: Steal from other workers
            if let Some(task) = self.try_steal() {
                self.execute(task);
                continue;
            }

            // PHASE 5: Backoff before parking
            let mut backoff = 0;

            loop {
                // Quick check for new work
                if !self.global.is_empty() {
                    break;
                }

                if backoff < SPIN_LIMIT {
                    std::hint::spin_loop();
                    backoff += 1;
                } else if backoff < SPIN_LIMIT + YIELD_LIMIT {
                    std::thread::yield_now();
                    backoff += 1;
                } else {
                    // Park with timeout based on next timer deadline
                    if let Some(timer) = &self.timer_driver {
                        if let Some(next_deadline) = timer.next_deadline() {
                            let now = timer.now();
                            if next_deadline > now {
                                let nanos = next_deadline.duration_since(now);
                                self.parker.park_timeout(Duration::from_nanos(nanos));
                            }
                            // If deadline is due or passed, don't park - loop back to process timers
                        } else {
                            // No pending timers, park indefinitely
                            self.parker.park();
                        }
                    } else {
                        // No timer driver, park indefinitely
                        self.parker.park();
                    }
                    break;
                }
            }
        }
    }

    /// Runs a single scheduling step.
    ///
    /// Returns `true` if a task was executed.
    pub(crate) fn run_once(&mut self) -> bool {
        if self.shutdown.load(Ordering::Relaxed) {
            return false;
        }

        // Process expired timers first
        if let Some(timer) = &self.timer_driver {
            let _ = timer.process_timers();
        }

        if let Some(task) = self.try_cancel_work() {
            self.execute(task);
            return true;
        }

        if let Some(task) = self.try_timed_work() {
            self.execute(task);
            return true;
        }

        if let Some(task) = self.try_ready_work() {
            self.execute(task);
            return true;
        }

        if let Some(task) = self.try_steal() {
            self.execute(task);
            return true;
        }

        false
    }

    /// Tries to get cancel work from global or local queues.
    pub(crate) fn try_cancel_work(&mut self) -> Option<TaskId> {
        // Global cancel has priority (cross-thread cancellations)
        if let Some(pt) = self.global.pop_cancel() {
            return Some(pt.task);
        }

        // Local cancel
        let mut local = self.local.lock().expect("local scheduler lock poisoned");
        let rng_hint = self.rng.next_u64();
        local.pop_cancel_only_with_hint(rng_hint)
    }

    /// Tries to get timed work from global or local queues.
    ///
    /// Uses EDF (Earliest Deadline First) ordering. Only returns tasks
    /// whose deadline has passed.
    pub(crate) fn try_timed_work(&mut self) -> Option<TaskId> {
        // Get current time from timer driver or use Time::ZERO (always ready)
        let now = self
            .timer_driver
            .as_ref()
            .map_or(Time::ZERO, TimerDriverHandle::now);

        // Global timed - EDF ordering, only pop if deadline is due
        if let Some(tt) = self.global.pop_timed_if_due(now) {
            return Some(tt.task);
        }

        // Local timed (already EDF ordered)
        let mut local = self.local.lock().expect("local scheduler lock poisoned");
        let rng_hint = self.rng.next_u64();
        local.pop_timed_only_with_hint(rng_hint)
    }

    /// Tries to get ready work from global or local queues.
    pub(crate) fn try_ready_work(&mut self) -> Option<TaskId> {
        // Global ready
        if let Some(pt) = self.global.pop_ready() {
            return Some(pt.task);
        }

        // Local ready
        let mut local = self.local.lock().expect("local scheduler lock poisoned");
        let rng_hint = self.rng.next_u64();
        local.pop_ready_only_with_hint(rng_hint)
    }

    /// Tries to steal work from other workers.
    ///
    /// Only steals from ready lanes to preserve cancel/timed priority semantics.
    pub(crate) fn try_steal(&mut self) -> Option<TaskId> {
        if self.stealers.is_empty() {
            return None;
        }

        let len = self.stealers.len();
        let start = self.rng.next_usize(len);

        for i in 0..len {
            let idx = (start + i) % len;
            let stealer = &self.stealers[idx];

            // Try to lock without blocking (skip if contended)
            if let Ok(mut victim) = stealer.try_lock() {
                let stolen = victim.steal_ready_batch(4);
                if !stolen.is_empty() {
                    // Take the first task to execute
                    let (first_task, _) = stolen[0];

                    // Push remaining stolen tasks to our local queue
                    if stolen.len() > 1 {
                        let mut local = self.local.lock().expect("local scheduler lock poisoned");
                        for (task, priority) in stolen.into_iter().skip(1) {
                            local.schedule(task, priority);
                        }
                    }

                    return Some(first_task);
                }
            }
        }

        None
    }

    /// Schedules a task locally in the appropriate lane.
    pub fn schedule_local(&self, task: TaskId, priority: u8) {
        let mut local = self.local.lock().expect("local scheduler lock poisoned");
        local.schedule(task, priority);
    }

    /// Schedules a cancelled task locally.
    pub fn schedule_local_cancel(&self, task: TaskId, priority: u8) {
        let mut local = self.local.lock().expect("local scheduler lock poisoned");
        local.schedule_cancel(task, priority);
    }

    /// Schedules a timed task locally.
    pub fn schedule_local_timed(&self, task: TaskId, deadline: Time) {
        let mut local = self.local.lock().expect("local scheduler lock poisoned");
        local.schedule_timed(task, deadline);
    }

    pub(crate) fn execute(&self, task_id: TaskId) {
        trace!(task_id = ?task_id, worker_id = self.id, "executing task");

        let (mut stored, task_cx, wake_state, priority, cx_inner) = {
            let mut state = self.state.lock().expect("runtime state lock poisoned");
            let Some(stored) = state.remove_stored_future(task_id) else {
                return;
            };
            let Some(record) = state.tasks.get_mut(task_id.arena_index()) else {
                return;
            };
            record.start_running();
            record.wake_state.clear();
            let priority = record
                .cx_inner
                .as_ref()
                .and_then(|inner| inner.read().ok().map(|cx| cx.budget.priority))
                .unwrap_or(0);
            let task_cx = record.cx.clone();
            let cx_inner = record.cx_inner.clone();
            let wake_state = Arc::clone(&record.wake_state);
            drop(state);
            (stored, task_cx, wake_state, priority, cx_inner)
        };

        let waker = Waker::from(Arc::new(ThreeLaneWaker {
            task_id,
            priority,
            wake_state: Arc::clone(&wake_state),
            global: Arc::clone(&self.global),
            parker: self.parker.clone(),
        }));
        if let Some(inner) = cx_inner.as_ref() {
            let cancel_waker = Waker::from(Arc::new(CancelLaneWaker {
                task_id,
                default_priority: priority,
                wake_state: Arc::clone(&wake_state),
                global: Arc::clone(&self.global),
                parker: self.parker.clone(),
                cx_inner: Arc::downgrade(inner),
            }));
            if let Ok(mut guard) = inner.write() {
                guard.cancel_waker = Some(cancel_waker);
            }
        }
        let mut cx = Context::from_waker(&waker);
        let _cx_guard = crate::cx::Cx::set_current(task_cx);

        match stored.poll(&mut cx) {
            Poll::Ready(()) => {
                let mut state = self.state.lock().expect("runtime state lock poisoned");
                if let Some(record) = state.tasks.get_mut(task_id.arena_index()) {
                    if !record.state.is_terminal() {
                        record.complete(Outcome::Ok(()));
                    }
                }

                let waiters = state.task_completed(task_id);
                for waiter in waiters {
                    if let Some(record) = state.tasks.get(waiter.arena_index()) {
                        let waiter_priority = record
                            .cx_inner
                            .as_ref()
                            .and_then(|inner| inner.read().ok().map(|cx| cx.budget.priority))
                            .unwrap_or(0);
                        if record.wake_state.notify() {
                            self.global.inject_ready(waiter, waiter_priority);
                            self.parker.unpark();
                        }
                    }
                }
            }
            Poll::Pending => {
                let mut state = self.state.lock().expect("runtime state lock poisoned");
                state.store_spawned_task(task_id, stored);
            }
        }
    }
}

struct ThreeLaneWaker {
    task_id: TaskId,
    priority: u8,
    wake_state: Arc<crate::record::task::TaskWakeState>,
    global: Arc<GlobalInjector>,
    parker: Parker,
}

impl ThreeLaneWaker {
    fn schedule(&self) {
        if self.wake_state.notify() {
            self.global.inject_ready(self.task_id, self.priority);
            self.parker.unpark();
        }
    }
}

impl Wake for ThreeLaneWaker {
    fn wake(self: Arc<Self>) {
        self.schedule();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.schedule();
    }
}

struct CancelLaneWaker {
    task_id: TaskId,
    default_priority: u8,
    wake_state: Arc<crate::record::task::TaskWakeState>,
    global: Arc<GlobalInjector>,
    parker: Parker,
    cx_inner: Weak<RwLock<CxInner>>,
}

impl CancelLaneWaker {
    fn schedule(&self) {
        let Some(inner) = self.cx_inner.upgrade() else {
            return;
        };
        let (cancel_requested, priority) = match inner.read() {
            Ok(guard) => {
                let priority = guard
                    .cancel_reason
                    .as_ref()
                    .map_or(self.default_priority, |reason| {
                        reason.cleanup_budget().priority
                    });
                (guard.cancel_requested, priority)
            }
            Err(_) => return,
        };

        if !cancel_requested {
            return;
        }

        if self.wake_state.notify() {
            self.global.inject_cancel(self.task_id, priority);
            self.parker.unpark();
        }
    }
}

impl Wake for CancelLaneWaker {
    fn wake(self: Arc<Self>) {
        self.schedule();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.schedule();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Budget, CancelReason, RegionId};
    use std::time::Duration;

    #[test]
    fn test_three_lane_scheduler_creation() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let scheduler = ThreeLaneScheduler::new(2, &state);

        assert!(!scheduler.is_shutdown());
        assert_eq!(scheduler.workers.len(), 2);
    }

    #[test]
    fn test_three_lane_worker_shutdown() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new(2, &state);

        let workers = scheduler.take_workers();
        assert_eq!(workers.len(), 2);

        // Spawn threads for workers
        let handles: Vec<_> = workers
            .into_iter()
            .map(|mut worker| {
                std::thread::spawn(move || {
                    worker.run_loop();
                })
            })
            .collect();

        // Let them run briefly
        std::thread::sleep(Duration::from_millis(10));

        // Signal shutdown
        scheduler.shutdown();

        // Join threads
        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_cancel_priority_over_ready() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new(1, &state);

        // Inject ready first, then cancel
        scheduler.inject_ready(TaskId::new_for_test(1, 1), 100);
        scheduler.inject_cancel(TaskId::new_for_test(1, 2), 50);

        // Worker should get cancel first
        let mut workers = scheduler.take_workers().into_iter();
        let mut worker = workers.next().unwrap();

        // Cancel should come first
        let task1 = worker.try_cancel_work();
        assert!(task1.is_some());
        assert_eq!(task1.unwrap(), TaskId::new_for_test(1, 2));

        // Ready should come after
        let task2 = worker.try_ready_work();
        assert!(task2.is_some());
        assert_eq!(task2.unwrap(), TaskId::new_for_test(1, 1));
    }

    #[test]
    fn test_stealing_only_from_ready_lane() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new(2, &state);

        // Add cancel and ready work to worker 0's local queue
        {
            let workers = &scheduler.workers;
            let mut local0 = workers[0].local.lock().unwrap();
            local0.schedule_cancel(TaskId::new_for_test(1, 1), 100);
            local0.schedule(TaskId::new_for_test(1, 2), 50);
            local0.schedule(TaskId::new_for_test(1, 3), 50);
        }

        // Worker 1 should only be able to steal ready work
        let mut workers = scheduler.take_workers().into_iter();
        let _ = workers.next().unwrap(); // Skip worker 0
        let mut thief_worker = workers.next().unwrap();

        // Stealing should only get ready tasks
        let stolen = thief_worker.try_steal();
        assert!(stolen.is_some());

        // The stolen task should be from ready lane (2 or 3)
        let stolen_id = stolen.unwrap();
        assert!(
            stolen_id == TaskId::new_for_test(1, 2) || stolen_id == TaskId::new_for_test(1, 3),
            "Expected ready task, got cancel task"
        );
    }

    #[test]
    fn execute_completes_task_and_schedules_waiter() {
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let region = state
            .lock()
            .expect("runtime state lock poisoned")
            .create_root_region(Budget::INFINITE);

        let task_id = {
            let mut guard = state.lock().expect("runtime state lock poisoned");
            let (task_id, _handle) = guard
                .create_task(region, Budget::INFINITE, async {})
                .expect("create task");
            task_id
        };
        let waiter_id = {
            let mut guard = state.lock().expect("runtime state lock poisoned");
            let (waiter_id, _handle) = guard
                .create_task(region, Budget::INFINITE, async {})
                .expect("create task");
            waiter_id
        };

        {
            let mut guard = state.lock().expect("runtime state lock poisoned");
            if let Some(record) = guard.tasks.get_mut(task_id.arena_index()) {
                record.add_waiter(waiter_id);
            }
        }

        let mut scheduler = ThreeLaneScheduler::new(1, &state);
        let worker = scheduler.take_workers().into_iter().next().unwrap();

        worker.execute(task_id);

        let completed = state
            .lock()
            .expect("runtime state lock poisoned")
            .tasks
            .get(task_id.arena_index())
            .is_none();
        assert!(completed, "task should be removed after completion");

        let scheduled_task = worker.global.pop_ready().map(|pt| pt.task);
        assert_eq!(scheduled_task, Some(waiter_id));
    }

    #[test]
    fn test_try_timed_work_checks_deadline() {
        use crate::time::{TimerDriverHandle, VirtualClock};

        // Create state with virtual clock timer driver
        let clock = Arc::new(VirtualClock::new());
        let mut state = RuntimeState::new();
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock.clone()));
        let state = Arc::new(Mutex::new(state));

        let mut scheduler = ThreeLaneScheduler::new(1, &state);

        // Inject a timed task with deadline at t=1000ns
        let task_id = TaskId::new_for_test(1, 1);
        let deadline = Time::from_nanos(1000);
        scheduler.inject_timed(task_id, deadline);

        let mut workers = scheduler.take_workers().into_iter();
        let mut worker = workers.next().unwrap();

        // At t=0, the task should NOT be ready (deadline not yet due)
        // try_timed_work should re-inject the task
        let result = worker.try_timed_work();
        assert!(result.is_none(), "task should not be ready before deadline");

        // Advance clock past deadline
        clock.advance(2000); // t=2000ns, past deadline of 1000ns

        // Now the task should be ready
        let result = worker.try_timed_work();
        assert_eq!(result, Some(task_id), "task should be ready after deadline");
    }

    #[test]
    fn test_worker_has_timer_driver_from_state() {
        use crate::time::{TimerDriverHandle, VirtualClock};

        // Create state with timer driver
        let clock = Arc::new(VirtualClock::new());
        let mut state = RuntimeState::new();
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock.clone()));
        let state = Arc::new(Mutex::new(state));

        let mut scheduler = ThreeLaneScheduler::new(1, &state);
        let workers = scheduler.take_workers();
        let worker = &workers[0];

        // Worker should have timer driver
        assert!(
            worker.timer_driver.is_some(),
            "worker should have timer driver from state"
        );

        // Timer driver should use the same clock
        let timer = worker.timer_driver.as_ref().unwrap();
        assert_eq!(timer.now(), Time::ZERO, "timer should start at zero");

        clock.advance(1000);
        assert_eq!(
            timer.now(),
            Time::from_nanos(1000),
            "timer should reflect clock advance"
        );
    }

    #[test]
    fn test_scheduler_timer_driver_propagates_to_workers() {
        // State without timer driver
        let state = Arc::new(Mutex::new(RuntimeState::new()));
        let mut scheduler = ThreeLaneScheduler::new(2, &state);

        // Workers should not have timer driver
        let workers = scheduler.take_workers();
        assert!(workers[0].timer_driver.is_none());
        assert!(workers[1].timer_driver.is_none());

        // Scheduler should not have timer driver
        assert!(scheduler.timer_driver.is_none());
    }

    #[test]
    fn test_run_once_processes_timers() {
        use crate::time::{TimerDriverHandle, VirtualClock};
        use std::sync::atomic::AtomicBool;
        use std::task::{Wake, Waker};

        // Waker that sets a flag when woken
        struct TestWaker(AtomicBool);
        impl Wake for TestWaker {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        // Create state with virtual clock timer driver
        let clock = Arc::new(VirtualClock::new());
        let mut state = RuntimeState::new();
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock.clone()));
        let state = Arc::new(Mutex::new(state));

        let mut scheduler = ThreeLaneScheduler::new(1, &state);

        // Get timer driver to register a timer
        let timer_driver = scheduler.timer_driver.as_ref().unwrap().clone();

        // Register a timer that expires at t=500ns
        let waker_flag = Arc::new(TestWaker(AtomicBool::new(false)));
        let waker = Waker::from(waker_flag.clone());
        let _handle = timer_driver.register(Time::from_nanos(500), waker);

        let mut workers = scheduler.take_workers().into_iter();
        let mut worker = workers.next().unwrap();

        // Timer should not be fired at t=0
        assert!(!waker_flag.0.load(Ordering::SeqCst));

        // run_once should process timers but not fire (deadline not reached)
        worker.run_once();
        assert!(
            !waker_flag.0.load(Ordering::SeqCst),
            "timer should not fire before deadline"
        );

        // Advance clock past deadline
        clock.advance(1000);

        // run_once should now fire the timer
        worker.run_once();
        assert!(
            waker_flag.0.load(Ordering::SeqCst),
            "timer should fire after deadline"
        );
    }

    #[test]
    fn test_timed_work_reinjection() {
        use crate::time::{TimerDriverHandle, VirtualClock};

        // Create state with virtual clock timer driver
        let clock = Arc::new(VirtualClock::new());
        let mut state = RuntimeState::new();
        state.set_timer_driver(TimerDriverHandle::with_virtual_clock(clock));
        let state = Arc::new(Mutex::new(state));

        let mut scheduler = ThreeLaneScheduler::new(1, &state);

        // Inject a timed task with deadline at t=1000ns
        let task_id = TaskId::new_for_test(1, 1);
        let deadline = Time::from_nanos(1000);
        scheduler.inject_timed(task_id, deadline);

        let mut workers = scheduler.take_workers().into_iter();
        let mut worker = workers.next().unwrap();

        // At t=0, task is not ready - should be re-injected
        let result = worker.try_timed_work();
        assert!(result.is_none());

        // The task should still be in the global queue (re-injected)
        let peeked = worker.global.pop_timed();
        assert!(
            peeked.is_some(),
            "task should be re-injected to global queue"
        );
        assert_eq!(peeked.unwrap().task, task_id);
    }

    #[test]
    fn cancel_waker_injects_cancel_lane() {
        let task_id = TaskId::new_for_test(1, 1);
        let cx_inner = Arc::new(RwLock::new(CxInner::new(
            RegionId::new_for_test(1, 0),
            task_id,
            Budget::INFINITE,
        )));
        {
            let mut guard = cx_inner.write().expect("lock poisoned");
            guard.cancel_requested = true;
            guard.cancel_reason = Some(CancelReason::timeout());
        }

        let wake_state = Arc::new(crate::record::task::TaskWakeState::new());
        let global = Arc::new(GlobalInjector::new());
        let parker = Parker::new();
        let waker = Waker::from(Arc::new(CancelLaneWaker {
            task_id,
            default_priority: Budget::INFINITE.priority,
            wake_state,
            global: Arc::clone(&global),
            parker,
            cx_inner: Arc::downgrade(&cx_inner),
        }));

        waker.wake_by_ref();

        let task = global.pop_cancel().map(|pt| pt.task);
        assert_eq!(task, Some(task_id));
    }
}
