    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    struct PanickingPayload {
        drops: Arc<AtomicUsize>,
    }

    impl Drop for PanickingPayload {
        fn drop(&mut self) {
            let already_panicking = std::thread::panicking();
            self.drops.fetch_add(1, Ordering::SeqCst);
            if !already_panicking {
                panic!("adversarial panic-payload destructor");
            }
        }
    }

    struct AdversarialWake {
        label: &'static str,
        wake_calls: Arc<AtomicUsize>,
        retirements: Arc<AtomicUsize>,
        wake_order: Arc<Mutex<Vec<&'static str>>>,
        wake_panic_attempts: Arc<AtomicUsize>,
        drop_panic_attempts: Arc<AtomicUsize>,
        panic_payload_drops: Arc<AtomicUsize>,
        panic_on_wake: bool,
        panic_on_drop: bool,
    }

    impl AdversarialWake {
        fn record_wake(&self) {
            self.wake_calls.fetch_add(1, Ordering::SeqCst);
            self.wake_order
                .lock()
                .expect("wake order lock")
                .push(self.label);
            if self.panic_on_wake {
                self.wake_panic_attempts.fetch_add(1, Ordering::SeqCst);
                std::panic::panic_any(PanickingPayload {
                    drops: Arc::clone(&self.panic_payload_drops),
                });
            }
        }
    }

    impl Wake for AdversarialWake {
        fn wake(self: Arc<Self>) {
            self.record_wake();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.record_wake();
        }
    }

    impl Drop for AdversarialWake {
        fn drop(&mut self) {
            self.retirements.fetch_add(1, Ordering::SeqCst);
            if self.panic_on_drop {
                self.drop_panic_attempts.fetch_add(1, Ordering::SeqCst);
                std::panic::panic_any(PanickingPayload {
                    drops: Arc::clone(&self.panic_payload_drops),
                });
            }
        }
    }

    struct LockAwareValue {
        drops: Arc<AtomicUsize>,
        drops_while_locked: Arc<AtomicUsize>,
        caller_lock: Arc<Mutex<()>>,
    }

    impl Drop for LockAwareValue {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
            if self.caller_lock.try_lock().is_err() {
                self.drops_while_locked.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    struct LockAwareWake {
        wake_calls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
        drops_while_locked: Arc<AtomicUsize>,
        caller_lock: Arc<Mutex<()>>,
    }

    impl Wake for LockAwareWake {
        fn wake(self: Arc<Self>) {
            self.wake_calls.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wake_calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Drop for LockAwareWake {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
            if self.caller_lock.try_lock().is_err() {
                self.drops_while_locked.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    struct AdversarialCancellationMetrics {
        calls: Arc<AtomicUsize>,
        calls_while_locked: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
        drops_while_locked: Arc<AtomicUsize>,
        panic_payload_drops: Arc<AtomicUsize>,
        caller_lock: Arc<Mutex<()>>,
        panic_on_call: bool,
        panic_on_drop: bool,
    }

    impl MetricsProvider for AdversarialCancellationMetrics {
        fn task_spawned(&self, _: RegionId, _: TaskId) {}

        fn task_completed(
            &self,
            _: TaskId,
            _: crate::observability::metrics::OutcomeKind,
            _: std::time::Duration,
        ) {
        }

        fn region_created(&self, _: RegionId, _: Option<RegionId>) {}

        fn region_closed(&self, _: RegionId, _: std::time::Duration) {}

        fn cancellation_requested(&self, _: RegionId, _: CancelKind) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.caller_lock.try_lock().is_err() {
                self.calls_while_locked.fetch_add(1, Ordering::SeqCst);
            }
            if self.panic_on_call {
                std::panic::panic_any(PanickingPayload {
                    drops: Arc::clone(&self.panic_payload_drops),
                });
            }
        }

        fn drain_completed(&self, _: RegionId, _: std::time::Duration) {}

        fn deadline_set(&self, _: RegionId, _: std::time::Duration) {}

        fn deadline_exceeded(&self, _: RegionId) {}

        fn deadline_warning(&self, _: &str, _: &'static str, _: std::time::Duration) {}

        fn deadline_violation(&self, _: &str, _: std::time::Duration) {}

        fn deadline_remaining(&self, _: &str, _: std::time::Duration) {}

        fn checkpoint_interval(&self, _: &str, _: std::time::Duration) {}

        fn task_stuck_detected(&self, _: &str) {}

        fn obligation_created(&self, _: RegionId) {}

        fn obligation_discharged(&self, _: RegionId) {}

        fn obligation_leaked(&self, _: RegionId) {}

        fn scheduler_tick(&self, _: usize, _: std::time::Duration) {}
    }

    impl Drop for AdversarialCancellationMetrics {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
            if self.caller_lock.try_lock().is_err() {
                self.drops_while_locked.fetch_add(1, Ordering::SeqCst);
            }
            if self.panic_on_drop {
                std::panic::panic_any(PanickingPayload {
                    drops: Arc::clone(&self.panic_payload_drops),
                });
            }
        }
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn cancel_wake_effects_isolate_wake_and_retirement_panics() {
        init_test("cancel_wake_effects_isolate_wake_and_retirement_panics");

        let first_wakes = Arc::new(AtomicUsize::new(0));
        let second_wakes = Arc::new(AtomicUsize::new(0));
        let third_wakes = Arc::new(AtomicUsize::new(0));
        let first_retirements = Arc::new(AtomicUsize::new(0));
        let second_retirements = Arc::new(AtomicUsize::new(0));
        let third_retirements = Arc::new(AtomicUsize::new(0));
        let wake_order = Arc::new(Mutex::new(Vec::new()));
        let wake_panic_attempts = Arc::new(AtomicUsize::new(0));
        let drop_panic_attempts = Arc::new(AtomicUsize::new(0));
        let panic_payload_drops = Arc::new(AtomicUsize::new(0));

        let target = |label,
                      wake_calls: &Arc<AtomicUsize>,
                      retirements: &Arc<AtomicUsize>,
                      panic_on_wake,
                      panic_on_drop| {
            Arc::new(CancelWaker::new(Waker::from(Arc::new(AdversarialWake {
                label,
                wake_calls: Arc::clone(wake_calls),
                retirements: Arc::clone(retirements),
                wake_order: Arc::clone(&wake_order),
                wake_panic_attempts: Arc::clone(&wake_panic_attempts),
                drop_panic_attempts: Arc::clone(&drop_panic_attempts),
                panic_payload_drops: Arc::clone(&panic_payload_drops),
                panic_on_wake,
                panic_on_drop,
            }))))
        };

        let mut first_batch = smallvec::SmallVec::<[Arc<CancelWaker>; 4]>::new();
        first_batch.push(target(
            "first",
            &first_wakes,
            &first_retirements,
            true,
            true,
        ));
        let mut effects = CancelWakeEffects::new(first_batch);

        let mut later_batch = smallvec::SmallVec::<[Arc<CancelWaker>; 4]>::new();
        later_batch.push(target(
            "second",
            &second_wakes,
            &second_retirements,
            false,
            false,
        ));
        later_batch.push(target(
            "third",
            &third_wakes,
            &third_retirements,
            false,
            false,
        ));
        effects.merge(CancelWakeEffects::new(later_batch));

        assert_eq!(effects.len(), 3);
        effects.dispatch();

        assert_eq!(first_wakes.load(Ordering::SeqCst), 1);
        assert_eq!(second_wakes.load(Ordering::SeqCst), 1);
        assert_eq!(third_wakes.load(Ordering::SeqCst), 1);
        assert_eq!(first_retirements.load(Ordering::SeqCst), 1);
        assert_eq!(second_retirements.load(Ordering::SeqCst), 1);
        assert_eq!(third_retirements.load(Ordering::SeqCst), 1);
        assert_eq!(wake_panic_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(drop_panic_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(panic_payload_drops.load(Ordering::SeqCst), 0);
        assert_eq!(
            *wake_order.lock().expect("wake order lock"),
            vec!["first", "second", "third"]
        );

        crate::test_complete!("cancel_wake_effects_isolate_wake_and_retirement_panics");
    }

    #[test]
    fn cancellation_observers_merge_without_wakers_and_isolate_panics() {
        init_test("cancellation_observers_merge_without_wakers_and_isolate_panics");

        let caller_lock = Arc::new(Mutex::new(()));
        let panic_payload_drops = Arc::new(AtomicUsize::new(0));
        let first_calls = Arc::new(AtomicUsize::new(0));
        let first_calls_while_locked = Arc::new(AtomicUsize::new(0));
        let first_drops = Arc::new(AtomicUsize::new(0));
        let first_drops_while_locked = Arc::new(AtomicUsize::new(0));
        let second_calls = Arc::new(AtomicUsize::new(0));
        let second_calls_while_locked = Arc::new(AtomicUsize::new(0));
        let second_drops = Arc::new(AtomicUsize::new(0));
        let second_drops_while_locked = Arc::new(AtomicUsize::new(0));
        let wake_calls = Arc::new(AtomicUsize::new(0));
        let wake_drops = Arc::new(AtomicUsize::new(0));
        let wake_drops_while_locked = Arc::new(AtomicUsize::new(0));

        let mut targets = smallvec::SmallVec::<[Arc<CancelWaker>; 4]>::new();
        targets.push(Arc::new(CancelWaker::new(Waker::from(Arc::new(
            LockAwareWake {
                wake_calls: Arc::clone(&wake_calls),
                drops: Arc::clone(&wake_drops),
                drops_while_locked: Arc::clone(&wake_drops_while_locked),
                caller_lock: Arc::clone(&caller_lock),
            },
        )))));
        let mut effects = CancelWakeEffects::new(targets);
        effects.push_region_cancellation_metric(
            Arc::new(AdversarialCancellationMetrics {
                calls: Arc::clone(&first_calls),
                calls_while_locked: Arc::clone(&first_calls_while_locked),
                drops: Arc::clone(&first_drops),
                drops_while_locked: Arc::clone(&first_drops_while_locked),
                panic_payload_drops: Arc::clone(&panic_payload_drops),
                caller_lock: Arc::clone(&caller_lock),
                panic_on_call: true,
                panic_on_drop: true,
            }),
            RegionId::testing_default(),
            CancelKind::Shutdown,
            None,
        );

        let mut observer_only = CancelWakeEffects::empty();
        observer_only.push_region_cancellation_metric(
            Arc::new(AdversarialCancellationMetrics {
                calls: Arc::clone(&second_calls),
                calls_while_locked: Arc::clone(&second_calls_while_locked),
                drops: Arc::clone(&second_drops),
                drops_while_locked: Arc::clone(&second_drops_while_locked),
                panic_payload_drops: Arc::clone(&panic_payload_drops),
                caller_lock: Arc::clone(&caller_lock),
                panic_on_call: false,
                panic_on_drop: false,
            }),
            RegionId::testing_default(),
            CancelKind::Shutdown,
            None,
        );
        assert!(observer_only.is_empty(), "is_empty remains Waker-only");
        effects.merge(observer_only);

        let dispatched = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            effects.dispatch();
        }));
        assert!(dispatched.is_ok());
        assert_eq!(first_calls.load(Ordering::SeqCst), 1);
        assert_eq!(first_drops.load(Ordering::SeqCst), 1);
        assert_eq!(second_calls.load(Ordering::SeqCst), 1);
        assert_eq!(second_drops.load(Ordering::SeqCst), 1);
        assert_eq!(wake_calls.load(Ordering::SeqCst), 1);
        assert_eq!(wake_drops.load(Ordering::SeqCst), 1);
        assert_eq!(first_calls_while_locked.load(Ordering::SeqCst), 0);
        assert_eq!(first_drops_while_locked.load(Ordering::SeqCst), 0);
        assert_eq!(second_calls_while_locked.load(Ordering::SeqCst), 0);
        assert_eq!(second_drops_while_locked.load(Ordering::SeqCst), 0);
        assert_eq!(wake_drops_while_locked.load(Ordering::SeqCst), 0);
        assert_eq!(panic_payload_drops.load(Ordering::SeqCst), 0);

        crate::test_complete!("cancellation_observers_merge_without_wakers_and_isolate_panics");
    }

    #[cfg(feature = "tracing-integration")]
    #[test]
    fn cancellation_protocol_diagnostic_contains_subscriber_panic() {
        use tracing_subscriber::prelude::*;

        struct PanickingLayer {
            attempts: Arc<AtomicUsize>,
        }

        impl<S> tracing_subscriber::Layer<S> for PanickingLayer
        where
            S: tracing::Subscriber,
        {
            fn on_event(
                &self,
                _: &tracing::Event<'_>,
                _: tracing_subscriber::layer::Context<'_, S>,
            ) {
                self.attempts.fetch_add(1, Ordering::SeqCst);
                panic!("adversarial cancellation diagnostic subscriber");
            }
        }

        let attempts = Arc::new(AtomicUsize::new(0));
        let mut effects = CancelWakeEffects::empty();
        effects.push_cancel_protocol_violation(
            "hostile cancellation validation",
            "Invalid { reason: deterministic fixture }".to_owned(),
        );
        let subscriber = tracing_subscriber::registry().with(PanickingLayer {
            attempts: Arc::clone(&attempts),
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tracing::subscriber::with_default(subscriber, || effects.dispatch());
        }));

        assert!(result.is_ok(), "subscriber panic must not escape dispatch");
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn abandoned_cancellation_effects_leak_value_and_waker_under_outer_lock() {
        init_test("abandoned_cancellation_effects_leak_value_and_waker_under_outer_lock");

        let caller_lock = Arc::new(Mutex::new(()));
        let value_drops = Arc::new(AtomicUsize::new(0));
        let value_drops_while_locked = Arc::new(AtomicUsize::new(0));
        let wake_calls = Arc::new(AtomicUsize::new(0));
        let waker_drops = Arc::new(AtomicUsize::new(0));
        let waker_drops_while_locked = Arc::new(AtomicUsize::new(0));
        let metric_calls = Arc::new(AtomicUsize::new(0));
        let metric_calls_while_locked = Arc::new(AtomicUsize::new(0));
        let metric_drops = Arc::new(AtomicUsize::new(0));
        let metric_drops_while_locked = Arc::new(AtomicUsize::new(0));
        let panic_payload_drops = Arc::new(AtomicUsize::new(0));

        let value = LockAwareValue {
            drops: Arc::clone(&value_drops),
            drops_while_locked: Arc::clone(&value_drops_while_locked),
            caller_lock: Arc::clone(&caller_lock),
        };
        let target = Arc::new(CancelWaker::new(Waker::from(Arc::new(LockAwareWake {
            wake_calls: Arc::clone(&wake_calls),
            drops: Arc::clone(&waker_drops),
            drops_while_locked: Arc::clone(&waker_drops_while_locked),
            caller_lock: Arc::clone(&caller_lock),
        }))));
        let mut targets = smallvec::SmallVec::<[Arc<CancelWaker>; 4]>::new();
        targets.push(target);
        let mut wakes = CancelWakeEffects::new(targets);
        wakes.push_region_cancellation_metric(
            Arc::new(AdversarialCancellationMetrics {
                calls: Arc::clone(&metric_calls),
                calls_while_locked: Arc::clone(&metric_calls_while_locked),
                drops: Arc::clone(&metric_drops),
                drops_while_locked: Arc::clone(&metric_drops_while_locked),
                panic_payload_drops: Arc::clone(&panic_payload_drops),
                caller_lock: Arc::clone(&caller_lock),
                panic_on_call: false,
                panic_on_drop: false,
            }),
            RegionId::testing_default(),
            CancelKind::Shutdown,
            None,
        );
        let effects = CancellationEffects::new(value, wakes);

        let guard = caller_lock.lock().expect("caller lock");
        drop(effects);
        assert_eq!(value_drops.load(Ordering::SeqCst), 0);
        assert_eq!(value_drops_while_locked.load(Ordering::SeqCst), 0);
        assert_eq!(wake_calls.load(Ordering::SeqCst), 0);
        assert_eq!(waker_drops.load(Ordering::SeqCst), 0);
        assert_eq!(waker_drops_while_locked.load(Ordering::SeqCst), 0);
        assert_eq!(metric_calls.load(Ordering::SeqCst), 0);
        assert_eq!(metric_calls_while_locked.load(Ordering::SeqCst), 0);
        assert_eq!(metric_drops.load(Ordering::SeqCst), 0);
        assert_eq!(metric_drops_while_locked.load(Ordering::SeqCst), 0);
        drop(guard);

        assert_eq!(value_drops.load(Ordering::SeqCst), 0);
        assert_eq!(value_drops_while_locked.load(Ordering::SeqCst), 0);
        assert_eq!(wake_calls.load(Ordering::SeqCst), 0);
        assert_eq!(waker_drops.load(Ordering::SeqCst), 0);
        assert_eq!(waker_drops_while_locked.load(Ordering::SeqCst), 0);
        assert_eq!(metric_calls.load(Ordering::SeqCst), 0);
        assert_eq!(metric_calls_while_locked.load(Ordering::SeqCst), 0);
        assert_eq!(metric_drops.load(Ordering::SeqCst), 0);
        assert_eq!(metric_drops_while_locked.load(Ordering::SeqCst), 0);
        assert_eq!(panic_payload_drops.load(Ordering::SeqCst), 0);

        crate::test_complete!(
            "abandoned_cancellation_effects_leak_value_and_waker_under_outer_lock"
        );
    }

    #[test]
    fn test_checkpoint_state_default() {
        init_test("test_checkpoint_state_default");
        let state = CheckpointState::new();
        crate::assert_with_log!(
            state.last_checkpoint.is_none(),
            "last_checkpoint",
            true,
            state.last_checkpoint.is_none()
        );
        crate::assert_with_log!(
            state.last_message.is_none(),
            "last_message",
            true,
            state.last_message.is_none()
        );
        crate::assert_with_log!(
            state.checkpoint_count == 0,
            "checkpoint_count",
            0,
            state.checkpoint_count
        );
        crate::assert_with_log!(
            state.history_capacity() == DEFAULT_CHECKPOINT_HISTORY_CAPACITY,
            "checkpoint history capacity",
            DEFAULT_CHECKPOINT_HISTORY_CAPACITY,
            state.history_capacity()
        );
        crate::assert_with_log!(
            state.history().is_empty(),
            "checkpoint history empty",
            true,
            state.history().is_empty()
        );
        crate::test_complete!("test_checkpoint_state_default");
    }

    #[test]
    fn test_checkpoint_state_record() {
        init_test("test_checkpoint_state_record");
        let mut state = CheckpointState::new();
        state.record();
        crate::assert_with_log!(
            state.last_checkpoint.is_some(),
            "last_checkpoint",
            true,
            state.last_checkpoint.is_some()
        );
        crate::assert_with_log!(
            state.last_message.is_none(),
            "last_message",
            true,
            state.last_message.is_none()
        );
        crate::assert_with_log!(
            state.checkpoint_count == 1,
            "checkpoint_count",
            1,
            state.checkpoint_count
        );
        state.record();
        crate::assert_with_log!(
            state.checkpoint_count == 2,
            "checkpoint_count 2",
            2,
            state.checkpoint_count
        );
        crate::test_complete!("test_checkpoint_state_record");
    }

    #[test]
    fn test_checkpoint_state_record_at() {
        init_test("test_checkpoint_state_record_at");
        let mut state = CheckpointState::new();
        let at = Time::from_nanos(123);

        state.record_at(at);

        crate::assert_with_log!(
            state.last_checkpoint == Some(at),
            "explicit checkpoint instant stored",
            format!("{at:?}"),
            format!("{:?}", state.last_checkpoint)
        );
        crate::assert_with_log!(
            state.last_message.is_none(),
            "record_at clears message",
            true,
            state.last_message.is_none()
        );
        crate::assert_with_log!(
            state.checkpoint_count == 1,
            "record_at increments count",
            1,
            state.checkpoint_count
        );
        crate::test_complete!("test_checkpoint_state_record_at");
    }

    #[test]
    fn test_checkpoint_state_record_with_message() {
        init_test("test_checkpoint_state_record_with_message");
        let mut state = CheckpointState::new();
        state.record_with_message("hello".to_string());
        crate::assert_with_log!(
            state.last_checkpoint.is_some(),
            "last_checkpoint",
            true,
            state.last_checkpoint.is_some()
        );
        crate::assert_with_log!(
            state.last_message.as_deref() == Some("hello"),
            "last_message",
            Some("hello"),
            state.last_message.as_deref()
        );
        crate::assert_with_log!(
            state.checkpoint_count == 1,
            "checkpoint_count",
            1,
            state.checkpoint_count
        );
        state.record();
        crate::assert_with_log!(
            state.last_message.is_none(),
            "last_message cleared",
            true,
            state.last_message.is_none()
        );
        crate::test_complete!("test_checkpoint_state_record_with_message");
    }

    #[test]
    fn test_checkpoint_state_record_with_message_at() {
        init_test("test_checkpoint_state_record_with_message_at");
        let mut state = CheckpointState::new();
        let at = Time::from_nanos(456);

        state.record_with_message_at("hello".to_string(), at);

        crate::assert_with_log!(
            state.last_checkpoint == Some(at),
            "explicit checkpoint instant stored",
            format!("{at:?}"),
            format!("{:?}", state.last_checkpoint)
        );
        crate::assert_with_log!(
            state.last_message.as_deref() == Some("hello"),
            "record_with_message_at stores message",
            Some("hello"),
            state.last_message.as_deref()
        );
        crate::assert_with_log!(
            state.checkpoint_count == 1,
            "record_with_message_at increments count",
            1,
            state.checkpoint_count
        );
        assert_eq!(
            state.history(),
            vec![CheckpointHistoryEntry {
                at,
                message: "hello".to_string()
            }]
        );
        crate::test_complete!("test_checkpoint_state_record_with_message_at");
    }

    #[test]
    fn checkpoint_history_preserves_oldest_to_newest_with_capacity() {
        init_test("checkpoint_history_preserves_oldest_to_newest_with_capacity");
        let mut state = CheckpointState::with_history_capacity(2);

        state.record_with_message_at("one".to_string(), Time::from_nanos(1));
        state.record_with_message_at("two".to_string(), Time::from_nanos(2));
        state.record_with_message_at("three".to_string(), Time::from_nanos(3));

        assert_eq!(
            state.history(),
            vec![
                CheckpointHistoryEntry {
                    at: Time::from_nanos(2),
                    message: "two".to_string(),
                },
                CheckpointHistoryEntry {
                    at: Time::from_nanos(3),
                    message: "three".to_string(),
                },
            ]
        );
        crate::test_complete!("checkpoint_history_preserves_oldest_to_newest_with_capacity");
    }

    #[test]
    fn checkpoint_history_can_be_disabled() {
        init_test("checkpoint_history_can_be_disabled");
        let mut state = CheckpointState::with_history_capacity(0);

        state.record_with_message_at("hidden".to_string(), Time::from_nanos(9));

        assert_eq!(state.last_message.as_deref(), Some("hidden"));
        assert!(state.history().is_empty());
        crate::test_complete!("checkpoint_history_can_be_disabled");
    }

    #[test]
    fn messageless_checkpoints_never_grow_history() {
        // AC2: the messageless `checkpoint()` hot path must stay allocation-free
        // with respect to the history ring — it records count/time only and
        // never appends. Mixing messageless records around a single message
        // proves only `record_with_message_at` touches the ring.
        init_test("messageless_checkpoints_never_grow_history");
        let mut state = CheckpointState::with_history_capacity(8);

        for n in 0..100u64 {
            state.record_at(Time::from_nanos(n));
        }
        assert!(
            state.history().is_empty(),
            "messageless checkpoints must not append history"
        );

        state.record_with_message_at("only-message".to_string(), Time::from_nanos(100));
        for n in 101..200u64 {
            state.record_at(Time::from_nanos(n));
        }

        let trail = state.history();
        assert_eq!(trail.len(), 1, "exactly one message checkpoint retained");
        assert_eq!(trail[0].message, "only-message");
        assert_eq!(trail[0].at, Time::from_nanos(100));
        assert_eq!(
            state.checkpoint_count, 200,
            "every checkpoint still counted"
        );
        assert_eq!(state.last_checkpoint, Some(Time::from_nanos(199)));
        crate::test_complete!("messageless_checkpoints_never_grow_history");
    }

    #[test]
    fn checkpoint_history_truncates_long_messages_on_char_boundary() {
        init_test("checkpoint_history_truncates_long_messages_on_char_boundary");
        let mut state = CheckpointState::new();
        let message = format!(
            "{}{}",
            "a".repeat(MAX_CHECKPOINT_HISTORY_MESSAGE_BYTES - 1),
            "é"
        );

        state.record_with_message_at(message, Time::from_nanos(1));

        let history = state.history();
        assert_eq!(history.len(), 1);
        assert_eq!(
            state
                .last_message
                .as_ref()
                .expect("last message should remain present")
                .len(),
            MAX_CHECKPOINT_HISTORY_MESSAGE_BYTES + 1
        );
        assert_eq!(
            history[0].message.len(),
            MAX_CHECKPOINT_HISTORY_MESSAGE_BYTES - 1
        );
        assert!(history[0].message.ends_with('a'));
        crate::test_complete!("checkpoint_history_truncates_long_messages_on_char_boundary");
    }

    #[test]
    fn test_checkpoint_state_message_overwrite() {
        init_test("test_checkpoint_state_message_overwrite");
        let mut state = CheckpointState::new();
        state.record_with_message("first".to_string());
        state.record_with_message("second".to_string());
        crate::assert_with_log!(
            state.last_message.as_deref() == Some("second"),
            "last_message overwrite",
            Some("second"),
            state.last_message.as_deref()
        );
        crate::assert_with_log!(
            state.checkpoint_count == 2,
            "checkpoint_count",
            2,
            state.checkpoint_count
        );
        crate::test_complete!("test_checkpoint_state_message_overwrite");
    }

    #[test]
    fn test_cx_inner_new() {
        init_test("test_cx_inner_new");
        let region = RegionId::testing_default();
        let task = TaskId::testing_default();
        let budget = Budget::new();
        let cx = CxInner::new(region, task, budget);
        crate::assert_with_log!(cx.region == region, "region", region, cx.region);
        crate::assert_with_log!(cx.task == task, "task", task, cx.task);
        crate::assert_with_log!(cx.budget == budget, "budget", budget, cx.budget);
        crate::assert_with_log!(
            cx.budget_baseline == budget,
            "budget_baseline",
            budget,
            cx.budget_baseline
        );
        crate::assert_with_log!(
            cx.capability_budget == CapabilityBudget::UNSPECIFIED,
            "capability_budget",
            CapabilityBudget::UNSPECIFIED,
            cx.capability_budget
        );
        crate::assert_with_log!(
            !cx.cancel_requested,
            "cancel_requested",
            false,
            cx.cancel_requested
        );
        crate::assert_with_log!(
            cx.cancel_reason.is_none(),
            "cancel_reason",
            true,
            cx.cancel_reason.is_none()
        );
        crate::assert_with_log!(cx.mask_depth == 0, "mask_depth", 0, cx.mask_depth);
        crate::test_complete!("test_cx_inner_new");
    }

    // =========================================================================
    // Wave 47 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn checkpoint_state_debug_clone_default() {
        let def = CheckpointState::default();
        assert!(def.last_checkpoint.is_none());
        assert!(def.last_message.is_none());
        assert_eq!(def.checkpoint_count, 0);
        let dbg = format!("{def:?}");
        assert!(dbg.contains("CheckpointState"), "{dbg}");

        let mut state = CheckpointState::new();
        state.record_with_message("progress".into());
        let cloned = state.clone();
        assert_eq!(cloned.checkpoint_count, 1);
        assert_eq!(cloned.last_message.as_deref(), Some("progress"));
    }

    #[test]
    fn cx_inner_debug() {
        let region = RegionId::testing_default();
        let task = TaskId::testing_default();
        let cx = CxInner::new(region, task, Budget::new());
        let dbg = format!("{cx:?}");
        assert!(dbg.contains("CxInner"), "{dbg}");
    }

    /// br-asupersync-soyet0 — `record_at` (the explicit-time form
    /// production callers use) updates checkpoint state without
    /// reaching for `wall_now()`. This guards against a future
    /// refactor accidentally re-introducing the ambient call inside
    /// the explicit path.
    #[test]
    fn record_at_uses_supplied_time() {
        let mut state = CheckpointState::new();
        state.record_at(Time::from_nanos(42));
        assert_eq!(state.last_checkpoint, Some(Time::from_nanos(42)));
        assert_eq!(state.checkpoint_count, 1);
        assert_eq!(state.last_message, None);
    }

    /// br-asupersync-soyet0 — `record_with_message_at` clears the
    /// stored message correctly and uses the supplied time.
    #[test]
    fn record_with_message_at_uses_supplied_time() {
        let mut state = CheckpointState::new();
        state.record_with_message_at("ckpt".to_string(), Time::from_nanos(7));
        assert_eq!(state.last_checkpoint, Some(Time::from_nanos(7)));
        assert_eq!(state.last_message.as_deref(), Some("ckpt"));
        assert_eq!(state.checkpoint_count, 1);
    }
