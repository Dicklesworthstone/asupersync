    use super::*;
    use crate::sync::ContendedMutex;
    use std::sync::{Mutex, Weak};

    /// Reentrant, persistently panicking provider for spawn-publication tests.
    pub struct PanickingSpawnMetrics {
        state: Mutex<Option<Weak<ContendedMutex<RuntimeState>>>>,
        spawn_attempts: AtomicUsize,
        reentry_successes: AtomicUsize,
        task_records_observed: AtomicUsize,
        stored_futures_observed: AtomicUsize,
        runnable_publications_observed: AtomicUsize,
    }

    impl PanickingSpawnMetrics {
        pub(crate) fn new() -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(None),
                spawn_attempts: AtomicUsize::new(0),
                reentry_successes: AtomicUsize::new(0),
                task_records_observed: AtomicUsize::new(0),
                stored_futures_observed: AtomicUsize::new(0),
                runnable_publications_observed: AtomicUsize::new(0),
            })
        }

        pub(crate) fn attach_state(&self, state: &Arc<ContendedMutex<RuntimeState>>) {
            *self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::downgrade(state));
        }

        pub(crate) fn spawn_attempts(&self) -> usize {
            self.spawn_attempts.load(Ordering::Relaxed)
        }

        pub(crate) fn reentry_successes(&self) -> usize {
            self.reentry_successes.load(Ordering::Relaxed)
        }

        pub(crate) fn task_records_observed(&self) -> usize {
            self.task_records_observed.load(Ordering::Relaxed)
        }

        pub(crate) fn stored_futures_observed(&self) -> usize {
            self.stored_futures_observed.load(Ordering::Relaxed)
        }

        pub(crate) fn runnable_publications_observed(&self) -> usize {
            self.runnable_publications_observed.load(Ordering::Relaxed)
        }
    }

    impl MetricsProvider for PanickingSpawnMetrics {
        fn task_spawned(&self, _: RegionId, task_id: TaskId) {
            self.spawn_attempts.fetch_add(1, Ordering::Relaxed);
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .and_then(Weak::upgrade);
            if let Some(state) = state
                && let Ok(mut runtime) = state.try_lock()
            {
                self.reentry_successes.fetch_add(1, Ordering::Relaxed);
                if let Some(task) = runtime.task(task_id) {
                    self.task_records_observed.fetch_add(1, Ordering::Relaxed);
                    if task
                        .cx_inner
                        .as_ref()
                        .is_some_and(|inner| inner.read().runnable_publication.is_published())
                    {
                        self.runnable_publications_observed
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
                if runtime.get_stored_future(task_id).is_some() {
                    self.stored_futures_observed.fetch_add(1, Ordering::Relaxed);
                }
            }
            panic!("adversarial task-spawn metrics callback");
        }

        fn task_completed(&self, _: TaskId, _: OutcomeKind, _: Duration) {}
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
