    use super::*;
    use crate::sync::ContendedMutex;
    use std::sync::{Mutex, Weak};

    /// Observes the actual completion lock and authoritative cleanup state.
    /// A failed try-lock is recorded instead of blocking the old implementation
    /// forever, so the same native test is a deterministic old-code failure.
    pub struct LifecycleCompletionMetrics {
        target: Mutex<Option<(Weak<ContendedMutex<RuntimeState>>, RegionId, TaskId)>>,
        events: Mutex<Vec<&'static str>>,
        reentries: AtomicUsize,
        retired: AtomicUsize,
        panic_on_lifecycle: bool,
    }

    impl LifecycleCompletionMetrics {
        pub fn new(panic_on_lifecycle: bool) -> Arc<Self> {
            Arc::new(Self {
                target: Mutex::new(None),
                events: Mutex::new(Vec::new()),
                reentries: AtomicUsize::new(0),
                retired: AtomicUsize::new(0),
                panic_on_lifecycle,
            })
        }

        pub fn arm(
            &self,
            state: &Arc<ContendedMutex<RuntimeState>>,
            region: RegionId,
            task: TaskId,
        ) {
            *self.target.lock().unwrap() = Some((Arc::downgrade(state), region, task));
        }

        fn observe(&self, event: &'static str, region: Option<RegionId>, task: Option<TaskId>) {
            let Some((state, target_region, target_task)) = self.target.lock().unwrap().clone()
            else {
                return;
            };
            if region.is_some_and(|region| region != target_region)
                || task.is_some_and(|task| task != target_task)
            {
                return;
            }
            self.events.lock().unwrap().push(event);
            if let Some(state) = state.upgrade()
                && let Ok(runtime) = state.try_lock()
            {
                self.reentries.fetch_add(1, Ordering::SeqCst);
                if runtime.region(target_region).is_none()
                    && runtime.pending_obligation_count() == 0
                    && runtime.task(target_task).is_none()
                {
                    self.retired.fetch_add(1, Ordering::SeqCst);
                }
            }
            assert!(
                !(self.panic_on_lifecycle && event != "completed"),
                "lifecycle observer sentinel: {event}"
            );
        }

        pub fn assert_completed(&self, discharged: &'static str) {
            assert_eq!(
                *self.events.lock().unwrap(),
                [discharged, "closed", "completed"]
            );
            assert_eq!(
                self.reentries.load(Ordering::SeqCst),
                3,
                "every callback reentered runtime state"
            );
            assert_eq!(
                self.retired.load(Ordering::SeqCst),
                3,
                "callbacks observed complete task/obligation/region retirement"
            );
        }
    }

    impl MetricsProvider for LifecycleCompletionMetrics {
        fn task_spawned(&self, _: RegionId, _: TaskId) {}
        fn task_completed(&self, task: TaskId, _: OutcomeKind, _: Duration) {
            self.observe("completed", None, Some(task));
        }
        fn region_created(&self, _: RegionId, _: Option<RegionId>) {}
        fn region_closed(&self, region: RegionId, _: Duration) {
            self.observe("closed", Some(region), None);
        }
        fn cancellation_requested(&self, _: RegionId, _: CancelKind) {}
        fn drain_completed(&self, _: RegionId, _: Duration) {}
        fn deadline_set(&self, _: RegionId, _: Duration) {}
        fn deadline_exceeded(&self, _: RegionId) {}
        fn deadline_warning(&self, _: &str, _: &'static str, _: Duration) {}
        fn deadline_violation(&self, _: &str, _: Duration) {}
        fn deadline_remaining(&self, _: &str, _: Duration) {}
        fn checkpoint_interval(&self, _: &str, _: Duration) {}
        fn task_stuck_detected(&self, _: &str) {}
        fn obligation_created(&self, _: RegionId) {}
        fn obligation_discharged(&self, region: RegionId) {
            self.observe("discharged", Some(region), None);
        }
        fn obligation_leaked(&self, region: RegionId) {
            self.observe("leaked", Some(region), None);
        }
        fn scheduler_tick(&self, _: usize, _: Duration) {}
    }

    struct PanickingDropPayload(Arc<AtomicUsize>);

    impl Drop for PanickingDropPayload {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
            panic!("adversarial panic-payload destructor");
        }
    }

    /// Deterministic adversarial provider shared by completion-path tests.
    pub struct PanickingCompletionMetrics {
        state: Mutex<Option<Weak<ContendedMutex<RuntimeState>>>>,
        completion_attempts: AtomicUsize,
        reentry_successes: AtomicUsize,
        completed_state_observed: AtomicUsize,
        completion_panics_remaining: AtomicUsize,
        panic_payload_drop_counter: Option<Arc<AtomicUsize>>,
        provider_drop_attempts: Option<Arc<AtomicUsize>>,
        provider_drop_while_state_locked: Option<Arc<AtomicUsize>>,
        panic_on_provider_drop: bool,
    }

    impl PanickingCompletionMetrics {
        fn with_completion_panics(completion_panics_remaining: usize) -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(None),
                completion_attempts: AtomicUsize::new(0),
                reentry_successes: AtomicUsize::new(0),
                completed_state_observed: AtomicUsize::new(0),
                completion_panics_remaining: AtomicUsize::new(completion_panics_remaining),
                panic_payload_drop_counter: None,
                provider_drop_attempts: None,
                provider_drop_while_state_locked: None,
                panic_on_provider_drop: false,
            })
        }

        pub(crate) fn panic_once() -> Arc<Self> {
            Self::with_completion_panics(1)
        }

        pub(crate) fn panic_persistently() -> Arc<Self> {
            Self::with_completion_panics(usize::MAX)
        }

        pub(crate) fn panic_with_panicking_drop_payload(
            drop_counter: Arc<AtomicUsize>,
        ) -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(None),
                completion_attempts: AtomicUsize::new(0),
                reentry_successes: AtomicUsize::new(0),
                completed_state_observed: AtomicUsize::new(0),
                completion_panics_remaining: AtomicUsize::new(1),
                panic_payload_drop_counter: Some(drop_counter),
                provider_drop_attempts: None,
                provider_drop_while_state_locked: None,
                panic_on_provider_drop: false,
            })
        }

        pub(crate) fn provider_drop_probe(
            drop_attempts: Arc<AtomicUsize>,
            drop_while_state_locked: Arc<AtomicUsize>,
        ) -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(None),
                completion_attempts: AtomicUsize::new(0),
                reentry_successes: AtomicUsize::new(0),
                completed_state_observed: AtomicUsize::new(0),
                completion_panics_remaining: AtomicUsize::new(0),
                panic_payload_drop_counter: None,
                provider_drop_attempts: Some(drop_attempts),
                provider_drop_while_state_locked: Some(drop_while_state_locked),
                panic_on_provider_drop: false,
            })
        }

        pub(crate) fn panic_callback_and_provider_drop(
            drop_attempts: Arc<AtomicUsize>,
        ) -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(None),
                completion_attempts: AtomicUsize::new(0),
                reentry_successes: AtomicUsize::new(0),
                completed_state_observed: AtomicUsize::new(0),
                completion_panics_remaining: AtomicUsize::new(1),
                panic_payload_drop_counter: None,
                provider_drop_attempts: Some(drop_attempts),
                provider_drop_while_state_locked: None,
                panic_on_provider_drop: true,
            })
        }

        pub(crate) fn attach_state(&self, state: &Arc<ContendedMutex<RuntimeState>>) {
            *self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::downgrade(state));
        }

        pub(crate) fn completion_attempts(&self) -> usize {
            self.completion_attempts.load(Ordering::Relaxed)
        }

        pub(crate) fn reentry_successes(&self) -> usize {
            self.reentry_successes.load(Ordering::Relaxed)
        }

        pub(crate) fn completed_state_observed(&self) -> usize {
            self.completed_state_observed.load(Ordering::Relaxed)
        }

        // See the note on `advance_transaction_generation` in
        // `database::sqlite`: `fetch_update` is deprecated on the pinned
        // nightly and absent from the stable subset, so the stable-compatible
        // spelling stays with an explicit allow.
        #[allow(deprecated)]
        fn should_panic_on_completion(&self) -> bool {
            self.completion_panics_remaining
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                    if remaining == 0 {
                        None
                    } else if remaining == usize::MAX {
                        Some(usize::MAX)
                    } else {
                        Some(remaining - 1)
                    }
                })
                .is_ok()
        }
    }

    impl MetricsProvider for PanickingCompletionMetrics {
        fn task_spawned(&self, _: RegionId, _: TaskId) {}

        fn task_completed(&self, task_id: TaskId, _: OutcomeKind, _: Duration) {
            self.completion_attempts.fetch_add(1, Ordering::Relaxed);
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .and_then(Weak::upgrade);
            if let Some(state) = state
                && let Ok(runtime) = state.try_lock()
            {
                self.reentry_successes.fetch_add(1, Ordering::Relaxed);
                if runtime.task(task_id).is_none() {
                    self.completed_state_observed
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            if self.should_panic_on_completion() {
                if let Some(drop_counter) = &self.panic_payload_drop_counter {
                    std::panic::panic_any(PanickingDropPayload(Arc::clone(drop_counter)));
                }
                panic!("adversarial task-completion metrics callback");
            }
        }

        fn region_created(&self, _: RegionId, _: Option<RegionId>) {}

        fn region_closed(&self, _: RegionId, _: Duration) {}

        fn cancellation_requested(&self, _: RegionId, _: CancelKind) {}

        fn drain_completed(&self, _: RegionId, _: Duration) {}

        fn deadline_set(&self, _: RegionId, _: Duration) {}

        fn deadline_exceeded(&self, _: RegionId) {}

        fn deadline_warning(&self, _: &str, _: &'static str, _: Duration) {}

        fn deadline_violation(&self, _: &str, _: Duration) {}

        fn deadline_remaining(&self, _: &str, _: Duration) {}

        fn checkpoint_interval(&self, _: &str, _: Duration) {}

        fn task_stuck_detected(&self, _: &str) {}

        fn obligation_created(&self, _: RegionId) {}

        fn obligation_discharged(&self, _: RegionId) {}

        fn obligation_leaked(&self, _: RegionId) {}

        fn scheduler_tick(&self, _: usize, _: Duration) {}
    }

    impl Drop for PanickingCompletionMetrics {
        fn drop(&mut self) {
            let Some(drop_attempts) = &self.provider_drop_attempts else {
                return;
            };
            drop_attempts.fetch_add(1, Ordering::Relaxed);

            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .and_then(Weak::upgrade);
            if state.is_some_and(|state| state.try_lock().is_err())
                && let Some(locked_drops) = &self.provider_drop_while_state_locked
            {
                locked_drops.fetch_add(1, Ordering::Relaxed);
            }
            assert!(
                !self.panic_on_provider_drop,
                "adversarial metrics-provider destructor"
            );
        }
    }
