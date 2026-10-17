    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::cx::macaroon::MacaroonToken;
    use crate::cx::registry::{RegistryCap, RegistryHandle};
    use crate::remote::{NodeId, RemoteCap};
    use crate::runtime::state::RuntimeState;
    use crate::security::key::AuthKey;
    use crate::types::Budget;
    use crate::types::SystemPressure;
    use crate::types::policy::FailFast;
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn actor_join_future_from_receiver<'a, A: Actor>(
        receiver: &'a mut crate::channel::oneshot::Receiver<Result<A, JoinError>>,
        terminal_state: &'a mut bool,
    ) -> ActorJoinFuture<'a, A> {
        let (sender, _mailbox_rx) = mpsc::channel::<A::Message>(4);
        ActorJoinFuture {
            inner: receiver.recv_uninterruptible(),
            cx_inner: std::sync::Weak::new(),
            sender,
            state: Arc::new(ActorStateCell::new(ActorState::Running)),
            terminal_state,
            drop_abort_defused: false,
            task: None,
            task_exit: None,
        }
    }

    fn counting_waker(counter: Arc<std::sync::atomic::AtomicUsize>) -> Waker {
        struct CountingWaker {
            counter: Arc<std::sync::atomic::AtomicUsize>,
        }

        impl std::task::Wake for CountingWaker {
            fn wake(self: Arc<Self>) {
                self.counter.fetch_add(1, Ordering::Relaxed);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.counter.fetch_add(1, Ordering::Relaxed);
            }
        }

        Waker::from(Arc::new(CountingWaker { counter }))
    }

    fn terminal_state_waker(
        state: Arc<ActorStateCell>,
        counter: Arc<std::sync::atomic::AtomicUsize>,
    ) -> Waker {
        struct TerminalStateWaker {
            state: Arc<ActorStateCell>,
            counter: Arc<std::sync::atomic::AtomicUsize>,
        }

        impl TerminalStateWaker {
            fn record_wake(&self) {
                assert_eq!(
                    self.state.load(),
                    ActorState::Stopped,
                    "join receiver must not wake before actor state is terminal"
                );
                self.counter.fetch_add(1, Ordering::Relaxed);
            }
        }

        impl std::task::Wake for TerminalStateWaker {
            fn wake(self: Arc<Self>) {
                self.record_wake();
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.record_wake();
            }
        }

        Waker::from(Arc::new(TerminalStateWaker { state, counter }))
    }

    /// Simple counter actor for testing.
    #[derive(Debug)]
    struct Counter {
        count: u64,
        started: bool,
        stopped: bool,
    }

    impl Counter {
        fn new() -> Self {
            Self {
                count: 0,
                started: false,
                stopped: false,
            }
        }
    }

    impl Actor for Counter {
        type Message = u64;

        fn on_start(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.started = true;
            Box::pin(async {})
        }

        fn handle(&mut self, _cx: &Cx, msg: u64) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.count += msg;
            Box::pin(async {})
        }

        fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.stopped = true;
            Box::pin(async {})
        }
    }

    /// The native spawn's task handle leaves the handle's and the join
    /// future's auto traits unchanged (br-asupersync-yvs9cx).
    #[test]
    fn actor_handle_and_join_future_keep_their_auto_traits() {
        fn assert_send_sync_unpin<T: Send + Sync + Unpin>() {}
        assert_send_sync_unpin::<ActorHandle<Counter>>();
        assert_send_sync_unpin::<ActorJoinFuture<'static, Counter>>();
    }

    struct FairnessProbeActor {
        handled: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Actor for FairnessProbeActor {
        type Message = ();

        fn handle(&mut self, _cx: &Cx, (): ()) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.handled.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {})
        }
    }

    /// A fully ready mailbox must still yield the worker after a bounded batch.
    ///
    /// Polling once is the important oracle: without the real `yield_now`
    /// scheduling point, the loop consumes all sixteen messages before it
    /// finally returns `Pending` on the empty mailbox. With the fairness yield,
    /// exactly the first batch of eight is handled.
    #[test]
    fn actor_ready_mailbox_yields_after_bounded_batch() {
        init_test("actor_ready_mailbox_yields_after_bounded_batch");

        let handled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let actor = FairnessProbeActor {
            handled: Arc::clone(&handled),
        };
        let (sender, mailbox) = mpsc::channel(16);
        for _ in 0..16 {
            sender.try_send(()).expect("queue ready actor message");
        }

        let state = Arc::new(ActorStateCell::new(ActorState::Created));
        let mut cell = ActorCell {
            mailbox,
            state: Arc::clone(&state),
        };
        let cx = Cx::for_testing();
        let mut actor_loop = Box::pin(run_actor_loop(actor, cx, &mut cell));
        let waker = Waker::noop().clone();
        let mut task_cx = Context::from_waker(&waker);

        assert!(matches!(
            actor_loop.as_mut().poll(&mut task_cx),
            Poll::Pending
        ));
        assert_eq!(
            handled.load(Ordering::SeqCst),
            8,
            "one poll must stop at the fairness batch boundary"
        );
        assert_eq!(state.load(), ActorState::Running);

        crate::test_complete!("actor_ready_mailbox_yields_after_bounded_batch");
    }

    fn assert_actor<A: Actor>() {}

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CapabilitySnapshot {
        same_registry: bool,
        same_remote: bool,
        same_io: bool,
        same_pressure: bool,
        same_macaroon: bool,
        has_timer: bool,
    }

    struct CapabilityProbeActor {
        snapshot: Arc<parking_lot::Mutex<Option<CapabilitySnapshot>>>,
        expected_registry: Arc<dyn RegistryCap>,
        expected_remote_node: String,
        expected_io: Arc<dyn crate::io::IoCap>,
        expected_pressure: Arc<SystemPressure>,
        expected_macaroon: Arc<MacaroonToken>,
    }

    impl Actor for CapabilityProbeActor {
        type Message = ();

        fn on_start(&mut self, cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            let child_registry = cx
                .registry_handle()
                .expect("actor child Cx must inherit registry")
                .as_arc();
            let child_io = cx
                .io_cap_handle()
                .expect("actor child Cx must inherit io capability");
            let child_pressure = cx
                .pressure_handle()
                .expect("actor child Cx must inherit system pressure");
            let child_macaroon = cx
                .macaroon_handle()
                .expect("actor child Cx must inherit macaroon");
            let remote_node = cx
                .remote()
                .map(|remote| remote.local_node().as_str().to_owned());

            *self.snapshot.lock() = Some(CapabilitySnapshot {
                same_registry: Arc::ptr_eq(&child_registry, &self.expected_registry),
                same_remote: remote_node.as_deref() == Some(self.expected_remote_node.as_str()),
                same_io: Arc::ptr_eq(&child_io, &self.expected_io),
                same_pressure: Arc::ptr_eq(&child_pressure, &self.expected_pressure),
                same_macaroon: Arc::ptr_eq(&child_macaroon, &self.expected_macaroon),
                has_timer: cx.has_timer(),
            });

            Box::pin(async {})
        }

        fn handle(&mut self, _cx: &Cx, _msg: ()) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            Box::pin(async {})
        }
    }

    fn capability_rich_parent_cx(
        runtime: &crate::lab::LabRuntime,
        region: crate::types::RegionId,
    ) -> (
        Cx,
        Arc<dyn RegistryCap>,
        Arc<dyn crate::io::IoCap>,
        Arc<SystemPressure>,
        Arc<MacaroonToken>,
    ) {
        let registry = crate::cx::NameRegistry::new();
        let registry_handle = RegistryHandle::new(Arc::new(registry));
        let registry_arc = registry_handle.as_arc();
        let io_cap: Arc<dyn crate::io::IoCap> = Arc::new(crate::io::LabIoCap::new_for_tests());
        let pressure = Arc::new(SystemPressure::with_headroom(0.25));
        let macaroon_token =
            MacaroonToken::mint(&AuthKey::from_seed(7), "scope:actor", "actor/tests");

        let parent_cx = Cx::new_with_drivers(
            region,
            crate::types::TaskId::new_for_test(77, 0),
            Budget::INFINITE,
            None,
            None,
            Some(Arc::clone(&io_cap)),
            runtime.state.timer_driver_handle(),
            None,
        )
        .with_registry_handle(Some(registry_handle))
        .with_remote_cap(RemoteCap::new().with_local_node(NodeId::new("actor-origin")))
        .with_pressure(Arc::clone(&pressure))
        .with_macaroon(macaroon_token);

        let macaroon = parent_cx
            .macaroon_handle()
            .expect("parent actor test Cx must retain macaroon");

        (parent_cx, registry_arc, io_cap, pressure, macaroon)
    }

    #[test]
    fn actor_trait_object_safety() {
        init_test("actor_trait_object_safety");

        // Verify Counter implements Actor with the right bounds
        assert_actor::<Counter>();

        crate::test_complete!("actor_trait_object_safety");
    }

    #[test]
    fn actor_handle_creation() {
        init_test("actor_handle_creation");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let result = scope.spawn_actor(&mut state, &cx, Counter::new(), 32);
        assert!(result.is_ok(), "spawn_actor should succeed");

        let (handle, stored) = result.unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        // Handle should have valid task ID
        let _tid = handle.task_id();

        // Actor should not be finished yet (not polled)
        assert!(!handle.is_finished());

        crate::test_complete!("actor_handle_creation");
    }

    #[test]
    fn actor_handle_abort_publishes_to_child_cx() {
        init_test("actor_handle_abort_publishes_to_child_cx");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let parent_cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);
        let (handle, _stored) = scope
            .spawn_actor(&mut state, &parent_cx, Counter::new(), 1)
            .expect("spawn actor");
        let actor_cx: Cx = Cx::from_inner(
            handle
                .inner
                .upgrade()
                .expect("actor handle must retain its live CxInner"),
        );

        handle.abort();

        assert!(
            actor_cx.is_cancel_requested(),
            "ActorHandle cancellation must publish through the actor Cx envelope"
        );
        crate::test_complete!("actor_handle_abort_publishes_to_child_cx");
    }

    #[test]
    fn spawn_actor_inherits_child_cx_capabilities() {
        init_test("spawn_actor_inherits_child_cx_capabilities");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);
        let (parent_cx, registry_arc, io_cap, pressure, macaroon) =
            capability_rich_parent_cx(&runtime, region);
        let snapshot = Arc::new(parking_lot::Mutex::new(None));

        let actor = CapabilityProbeActor {
            snapshot: Arc::clone(&snapshot),
            expected_registry: registry_arc,
            expected_remote_node: "actor-origin".to_string(),
            expected_io: io_cap,
            expected_pressure: pressure,
            expected_macaroon: macaroon,
        };

        let (handle, stored) = scope
            .spawn_actor(&mut runtime.state, &parent_cx, actor, 8)
            .expect("spawn actor");
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_idle();

        let observed = snapshot
            .lock()
            .clone()
            .expect("actor on_start should capture inherited capabilities");
        assert_eq!(
            observed,
            CapabilitySnapshot {
                same_registry: true,
                same_remote: true,
                same_io: true,
                same_pressure: true,
                same_macaroon: true,
                has_timer: true,
            }
        );

        drop(handle);
        runtime.run_until_quiescent();

        crate::test_complete!("spawn_actor_inherits_child_cx_capabilities");
    }

    #[test]
    fn spawn_supervised_actor_inherits_child_cx_capabilities() {
        init_test("spawn_supervised_actor_inherits_child_cx_capabilities");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);
        let (parent_cx, registry_arc, io_cap, pressure, macaroon) =
            capability_rich_parent_cx(&runtime, region);
        let snapshot = Arc::new(parking_lot::Mutex::new(None));

        let snapshot_for_factory = Arc::clone(&snapshot);
        let strategy = crate::supervision::SupervisionStrategy::Stop;
        let (handle, stored) = scope
            .spawn_supervised_actor(
                &mut runtime.state,
                &parent_cx,
                move || CapabilityProbeActor {
                    snapshot: Arc::clone(&snapshot_for_factory),
                    expected_registry: Arc::clone(&registry_arc),
                    expected_remote_node: "actor-origin".to_string(),
                    expected_io: Arc::clone(&io_cap),
                    expected_pressure: Arc::clone(&pressure),
                    expected_macaroon: Arc::clone(&macaroon),
                },
                strategy,
                8,
            )
            .expect("spawn supervised actor");
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_idle();

        let observed = snapshot
            .lock()
            .clone()
            .expect("supervised actor on_start should capture inherited capabilities");
        assert_eq!(
            observed,
            CapabilitySnapshot {
                same_registry: true,
                same_remote: true,
                same_io: true,
                same_pressure: true,
                same_macaroon: true,
                has_timer: true,
            }
        );

        drop(handle);
        runtime.run_until_quiescent();

        crate::test_complete!("spawn_supervised_actor_inherits_child_cx_capabilities");
    }

    #[test]
    fn actor_id_generation_distinct() {
        init_test("actor_id_generation_distinct");

        let id1 = ActorId::from_task(TaskId::new_for_test(1, 1));
        let id2 = ActorId::from_task(TaskId::new_for_test(1, 2));
        assert!(id1 != id2, "generation must distinguish actor reuse");

        crate::test_complete!("actor_id_generation_distinct");
    }

    #[test]
    fn actor_ref_is_cloneable() {
        init_test("actor_ref_is_cloneable");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_actor(&mut state, &cx, Counter::new(), 32)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        // Get multiple refs
        let ref1 = handle.sender();
        let ref2 = ref1.clone();

        // Actor identity is preserved across clones
        assert_eq!(ref1.actor_id(), handle.actor_id());
        assert_eq!(ref2.actor_id(), handle.actor_id());

        // Actor is alive at creation time (even before first poll)
        assert!(ref1.is_alive());
        assert!(ref2.is_alive());

        // Both should be open
        assert!(!ref1.is_closed());
        assert!(!ref2.is_closed());

        crate::test_complete!("actor_ref_is_cloneable");
    }

    // ---- E2E Actor Scenarios ----

    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    /// Observable counter actor: writes final count to shared state during on_stop.
    /// Used by E2E tests to verify actor behavior without needing join().
    struct ObservableCounter {
        count: u64,
        on_stop_count: Arc<AtomicU64>,
        started: Arc<AtomicBool>,
        stopped: Arc<AtomicBool>,
    }

    impl ObservableCounter {
        fn new(
            on_stop_count: Arc<AtomicU64>,
            started: Arc<AtomicBool>,
            stopped: Arc<AtomicBool>,
        ) -> Self {
            Self {
                count: 0,
                on_stop_count,
                started,
                stopped,
            }
        }
    }

    impl Actor for ObservableCounter {
        type Message = u64;

        fn on_start(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.started.store(true, Ordering::SeqCst);
            Box::pin(async {})
        }

        fn handle(&mut self, _cx: &Cx, msg: u64) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.count += msg;
            Box::pin(async {})
        }

        fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.on_stop_count.store(self.count, Ordering::SeqCst);
            self.stopped.store(true, Ordering::SeqCst);
            Box::pin(async {})
        }
    }

    fn observable_state() -> (Arc<AtomicU64>, Arc<AtomicBool>, Arc<AtomicBool>) {
        (
            Arc::new(AtomicU64::new(u64::MAX)),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
    }

    /// E2E: Actor processes all messages sent before channel disconnect.
    /// Verifies: messages delivered, on_start called, on_stop called.
    #[test]
    fn actor_processes_all_messages() {
        init_test("actor_processes_all_messages");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (on_stop_count, started, stopped) = observable_state();
        let actor = ObservableCounter::new(on_stop_count.clone(), started.clone(), stopped.clone());

        let (handle, stored) = scope
            .spawn_actor(&mut runtime.state, &cx, actor, 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // Pre-fill mailbox with 5 messages (each adding 1)
        for _ in 0..5 {
            handle.try_send(1).unwrap();
        }

        // Drop handle to disconnect channel — actor will process buffered
        // messages via recv, then see Disconnected and stop gracefully.
        drop(handle);

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_quiescent();

        assert_eq!(
            on_stop_count.load(Ordering::SeqCst),
            5,
            "all messages processed"
        );
        assert!(started.load(Ordering::SeqCst), "on_start was called");
        assert!(stopped.load(Ordering::SeqCst), "on_stop was called");

        crate::test_complete!("actor_processes_all_messages");
    }

    /// E2E: Mailbox drain on cancellation.
    /// Pre-fills mailbox, cancels actor before it runs, verifies all messages
    /// are still processed during the drain phase (no silent drops).
    #[test]
    fn actor_drains_mailbox_on_cancel() {
        init_test("actor_drains_mailbox_on_cancel");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (on_stop_count, started, stopped) = observable_state();
        let actor = ObservableCounter::new(on_stop_count.clone(), started.clone(), stopped.clone());

        let (handle, stored) = scope
            .spawn_actor(&mut runtime.state, &cx, actor, 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // Pre-fill mailbox with 5 messages
        for _ in 0..5 {
            handle.try_send(1).unwrap();
        }

        // Cancel the actor BEFORE running.
        // The actor loop will: on_start → check cancel → break → drain → on_stop
        handle.stop();
        let stopped_ref = handle.sender();
        assert!(
            stopped_ref.is_closed(),
            "stop() seals the mailbox immediately"
        );
        assert!(
            matches!(handle.try_send(99), Err(SendError::Disconnected(99))),
            "stop() must reject new messages instead of extending shutdown"
        );

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_quiescent();

        // All 5 messages processed during drain phase
        assert_eq!(
            on_stop_count.load(Ordering::SeqCst),
            5,
            "drain processed all messages"
        );
        assert!(started.load(Ordering::SeqCst), "on_start was called");
        assert!(stopped.load(Ordering::SeqCst), "on_stop was called");

        crate::test_complete!("actor_drains_mailbox_on_cancel");
    }

    /// A graceful stop must invoke every already-committed message even when
    /// one drain handler panics. The first panic remains the terminal task/join
    /// outcome, and cleanup still runs after the FIFO tail.
    #[test]
    fn native_actor_graceful_drain_continues_after_handler_panic() {
        #[derive(Debug)]
        struct DrainPanicActor {
            events: Arc<parking_lot::Mutex<Vec<&'static str>>>,
        }

        impl Actor for DrainPanicActor {
            type Message = u8;

            fn on_start(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.events.lock().push("start");
                Box::pin(async {})
            }

            fn handle(
                &mut self,
                _cx: &Cx,
                msg: u8,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                match msg {
                    0 => self.events.lock().push("handle-0"),
                    1 => {
                        self.events.lock().push("handle-1-panic");
                        panic!("graceful drain handler panic");
                    }
                    2 => self.events.lock().push("handle-2"),
                    3 => self.events.lock().push("handle-3"),
                    _ => unreachable!("fixture message outside 0..=3"),
                }
                Box::pin(async {})
            }

            fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.events.lock().push("stop");
                Box::pin(async {})
            }
        }

        init_test("native_actor_graceful_drain_continues_after_handler_panic");
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("build native current-thread runtime");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);
        let events = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let actor = DrainPanicActor {
            events: Arc::clone(&events),
        };
        let (mut handle, mut stored) = scope
            .spawn_actor(&mut state, &cx, actor, 8)
            .expect("spawn actor");

        for msg in 0..=3 {
            handle.try_send(msg).expect("queue drain fixture");
        }
        handle.stop();

        let task_outcome = runtime.block_on(std::future::poll_fn(|task_cx| stored.poll(task_cx)));
        match task_outcome {
            Outcome::Panicked(payload) => assert_eq!(
                payload.message(),
                "graceful drain handler panic",
                "task outcome preserves first drain panic"
            ),
            other => panic!("expected panicked actor task, got {other:?}"),
        }

        match runtime.block_on(handle.join(&cx)) {
            Err(JoinError::Panicked(payload)) => assert_eq!(
                payload.message(),
                "graceful drain handler panic",
                "join preserves first drain panic"
            ),
            other => panic!("expected panicked actor join, got {other:?}"),
        }
        assert_eq!(
            *events.lock(),
            vec![
                "start",
                "handle-0",
                "handle-1-panic",
                "handle-2",
                "handle-3",
                "stop",
            ],
            "graceful drain must invoke the committed FIFO tail and cleanup after a handler panic"
        );
        assert_eq!(handle.state.load(), ActorState::Stopped);

        crate::test_complete!("native_actor_graceful_drain_continues_after_handler_panic");
    }

    /// An abort that lands while a graceful drain is running ends the drain:
    /// the handler in flight finishes, the rest of the buffered tail is
    /// dropped unhandled, and on_stop still runs.
    #[test]
    fn abort_during_a_graceful_drain_drops_the_rest_of_the_tail() {
        #[derive(Debug)]
        struct SlowFirstActor {
            events: Arc<parking_lot::Mutex<Vec<&'static str>>>,
        }

        impl Actor for SlowFirstActor {
            type Message = u8;

            fn on_start(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.events.lock().push("start");
                Box::pin(async {})
            }

            fn handle(
                &mut self,
                cx: &Cx,
                msg: u8,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                if msg == 0 {
                    self.events.lock().push("handle-0");
                    // Parks until the actor is cancelled.
                    let cx = cx.clone();
                    return Box::pin(std::future::poll_fn(move |_| {
                        if cx.checkpoint().is_err() {
                            Poll::Ready(())
                        } else {
                            Poll::Pending
                        }
                    }));
                }
                self.events.lock().push("handle-later");
                Box::pin(async {})
            }

            fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.events.lock().push("stop");
                Box::pin(async {})
            }
        }

        init_test("abort_during_a_graceful_drain_drops_the_rest_of_the_tail");
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);
        let events = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let actor = SlowFirstActor {
            events: Arc::clone(&events),
        };
        let (handle, mut stored) = scope
            .spawn_actor(&mut state, &cx, actor, 8)
            .expect("spawn actor");
        for msg in 0..=3 {
            handle.try_send(msg).expect("queue drain fixture");
        }
        handle.stop();

        let mut task_cx = Context::from_waker(Waker::noop());
        assert!(
            stored.poll(&mut task_cx).is_pending(),
            "the drain parks in the first handler"
        );
        assert_eq!(*events.lock(), vec!["start", "handle-0"]);

        handle.abort();
        assert!(
            stored.poll(&mut task_cx).is_ready(),
            "the aborted drain finishes without handling the tail"
        );
        assert_eq!(
            *events.lock(),
            vec!["start", "handle-0", "stop"],
            "messages 1..=3 are dropped once the abort lands"
        );

        crate::test_complete!("abort_during_a_graceful_drain_drops_the_rest_of_the_tail");
    }

    /// E2E: ActorRef liveness tracks actor lifecycle (Created -> Stopping -> Stopped).
    #[test]
    fn actor_ref_is_alive_transitions() {
        init_test("actor_ref_is_alive_transitions");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (on_stop_count, started, stopped) = observable_state();
        let actor = ObservableCounter::new(on_stop_count.clone(), started.clone(), stopped.clone());

        let (handle, stored) = scope
            .spawn_actor(&mut runtime.state, &cx, actor, 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        let actor_ref = handle.sender();
        assert!(actor_ref.is_alive(), "created actor should be alive");
        assert_eq!(actor_ref.actor_id(), handle.actor_id());

        handle.stop();
        assert!(actor_ref.is_alive(), "stopping actor is still alive");

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_quiescent();

        assert!(
            handle.is_finished(),
            "actor should be finished after stop + run"
        );
        assert!(!actor_ref.is_alive(), "finished actor is not alive");

        // Sanity: the actor ran its hooks.
        assert!(started.load(Ordering::SeqCst), "on_start was called");
        assert!(stopped.load(Ordering::SeqCst), "on_stop was called");
        assert_ne!(
            on_stop_count.load(Ordering::SeqCst),
            u64::MAX,
            "on_stop_count updated"
        );

        crate::test_complete!("actor_ref_is_alive_transitions");
    }

    #[test]
    fn dropped_join_future_marks_actor_stopping_like_abort() {
        init_test("dropped_join_future_marks_actor_stopping_like_abort");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (on_stop_count, started, stopped) = observable_state();
        let actor = ObservableCounter::new(on_stop_count.clone(), started.clone(), stopped.clone());

        let (mut handle, stored) = scope
            .spawn_actor(&mut runtime.state, &cx, actor, 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_idle();
        assert_eq!(
            handle.state.load(),
            ActorState::Running,
            "actor should be running before join drop requests abort"
        );
        let actor_cx: Cx = Cx::from_inner(
            handle
                .inner
                .upgrade()
                .expect("actor handle must retain its live CxInner"),
        );

        drop(handle.join(&cx));

        assert_eq!(
            handle.state.load(),
            ActorState::Stopping,
            "dropping join future should mirror ActorHandle::abort state transition"
        );
        assert!(
            actor_cx.is_cancel_requested(),
            "ActorJoinFuture cancellation must publish through the actor Cx envelope"
        );
        assert!(
            matches!(handle.try_send(1), Err(SendError::Disconnected(1))),
            "join-drop abort must seal the mailbox immediately"
        );

        runtime.run_until_quiescent();
        assert!(
            handle.is_finished(),
            "actor should stop after join future drop"
        );
        assert!(started.load(Ordering::SeqCst), "on_start should have run");
        assert!(stopped.load(Ordering::SeqCst), "on_stop should have run");
        assert_eq!(
            on_stop_count.load(Ordering::SeqCst),
            0,
            "idle actor should stop without processing phantom messages"
        );

        crate::test_complete!("dropped_join_future_marks_actor_stopping_like_abort");
    }

    #[test]
    fn actor_stop_unblocks_pending_sender_with_disconnect() {
        init_test("actor_stop_unblocks_pending_sender_with_disconnect");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_actor(&mut state, &cx, Counter::new(), 1)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        handle.try_send(1).expect("fill mailbox");
        let sender = handle.sender();
        let mut send_fut = Box::pin(sender.send(&cx, 2));
        let wake_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let waker = counting_waker(Arc::clone(&wake_count));
        let mut task_cx = Context::from_waker(&waker);

        let first_poll = send_fut.as_mut().poll(&mut task_cx);
        assert!(
            matches!(first_poll, Poll::Pending),
            "send should wait while the mailbox is full"
        );

        handle.stop();

        assert_eq!(
            wake_count.load(Ordering::SeqCst),
            1,
            "stop() must wake a sender blocked on mailbox capacity"
        );
        let second_poll = send_fut.as_mut().poll(&mut task_cx);
        assert!(
            matches!(
                second_poll,
                Poll::Ready(Outcome::Err(SendError::Disconnected(2)))
            ),
            "pending sender must fail fast once stop seals the mailbox"
        );

        crate::test_complete!("actor_stop_unblocks_pending_sender_with_disconnect");
    }

    /// E2E: Supervised actor crashes restart under Restart strategy.
    #[test]
    fn supervised_actor_panic_restarts_under_restart_strategy() {
        use std::sync::atomic::AtomicU32;

        #[derive(Debug)]
        struct PanickingCounter {
            count: u64,
            panic_on: u64,
            final_count: Arc<AtomicU64>,
        }

        impl Actor for PanickingCounter {
            type Message = u64;

            fn handle(
                &mut self,
                _cx: &Cx,
                msg: u64,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                assert!(msg != self.panic_on, "threshold exceeded: {msg}");
                self.count += msg;
                Box::pin(async {})
            }

            fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.final_count.store(self.count, Ordering::SeqCst);
                Box::pin(async {})
            }
        }

        init_test("supervised_actor_panic_restarts_under_restart_strategy");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let final_count = Arc::new(AtomicU64::new(u64::MAX));
        let restart_count = Arc::new(AtomicU32::new(0));
        let fc = final_count.clone();
        let rc = restart_count.clone();

        let strategy = crate::supervision::SupervisionStrategy::Restart(
            crate::supervision::RestartConfig::new(3, std::time::Duration::from_secs(60))
                .with_backoff(crate::supervision::BackoffStrategy::None),
        );

        let (mut handle, stored) = scope
            .spawn_supervised_actor(
                &mut runtime.state,
                &cx,
                move || {
                    rc.fetch_add(1, Ordering::Relaxed);
                    PanickingCounter {
                        count: 0,
                        panic_on: 999,
                        final_count: fc.clone(),
                    }
                },
                strategy,
                32,
            )
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // Message sequence:
        // 1. Normal message (count += 1)
        // 2. Panic trigger
        // 3. Queued message that should run on the restarted actor instance
        handle.try_send(1).unwrap();
        handle.try_send(999).unwrap(); // triggers panic
        handle.try_send(1).unwrap();

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_idle();
        handle.abort();
        runtime.run_until_quiescent();

        let join = futures_lite::future::block_on(handle.join(&cx));
        let actor = join.expect("aborting the restarted actor should still return final state");
        assert_eq!(
            restart_count.load(Ordering::SeqCst),
            2,
            "panic must trigger exactly one supervised restart, got {} factory calls",
            restart_count.load(Ordering::SeqCst)
        );
        assert_eq!(
            actor.count, 1,
            "restarted actor should keep the post-crash message count"
        );
        assert_eq!(
            final_count.load(Ordering::SeqCst),
            1,
            "restarted actor should process the queued post-crash message before abort"
        );

        crate::test_complete!("supervised_actor_panic_restarts_under_restart_strategy");
    }

    #[test]
    fn supervised_restart_window_expires_without_timer_driver() {
        use std::thread;

        init_test("supervised_restart_window_expires_without_timer_driver");

        let region_id = RegionId::new_for_test(0, 1);
        let cx = Cx::new(region_id, TaskId::new_for_test(1, 1), Budget::INFINITE);
        let mut supervisor =
            crate::supervision::Supervisor::new(crate::supervision::SupervisionStrategy::Restart(
                crate::supervision::RestartConfig::new(1, Duration::from_millis(2))
                    .with_backoff(crate::supervision::BackoffStrategy::None),
            ));
        let outcome = Outcome::Err(());
        let task_id = TaskId::new_for_test(2, 1);

        let first = supervisor.on_failure(
            task_id,
            region_id,
            None,
            &outcome,
            supervised_restart_timestamp(&cx),
        );
        assert!(
            matches!(
                first,
                crate::supervision::SupervisionDecision::Restart { attempt: 1, .. }
            ),
            "first failure should allow a restart"
        );

        thread::sleep(Duration::from_millis(5));

        let second = supervisor.on_failure(
            task_id,
            region_id,
            None,
            &outcome,
            supervised_restart_timestamp(&cx),
        );
        assert!(
            matches!(
                second,
                crate::supervision::SupervisionDecision::Restart { attempt: 1, .. }
            ),
            "wall-clock fallback must let the restart window expire without a timer driver"
        );

        crate::test_complete!("supervised_restart_window_expires_without_timer_driver");
    }

    #[test]
    fn supervised_restart_delay_uses_explicit_timer_driver_without_ambient_cx() {
        init_test("supervised_restart_delay_uses_explicit_timer_driver_without_ambient_cx");

        let clock = Arc::new(crate::time::VirtualClock::new());
        let timer = crate::time::TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let cx = Cx::new_with_drivers(
            RegionId::new_for_test(4, 0),
            TaskId::new_for_test(4, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let state = ActorStateCell::new(ActorState::Running);
        let mut wait = Box::pin(wait_supervised_restart_delay(
            &cx,
            &state,
            Duration::from_millis(5),
        ));
        let mut task_cx = Context::from_waker(Waker::noop());

        assert!(matches!(
            Future::poll(wait.as_mut(), &mut task_cx),
            Poll::Pending
        ));

        clock.advance(5_000_000);
        assert_eq!(
            timer.process_timers(),
            1,
            "restart delay must register with the explicit timer driver"
        );

        assert!(matches!(
            Future::poll(wait.as_mut(), &mut task_cx),
            Poll::Ready(Outcome::Ok(()))
        ));

        crate::test_complete!(
            "supervised_restart_delay_uses_explicit_timer_driver_without_ambient_cx"
        );
    }

    #[test]
    fn supervised_actor_stop_prevents_restart_after_panic() {
        use std::sync::atomic::AtomicU32;

        #[derive(Debug)]
        struct StopThenPanicActor;

        impl Actor for StopThenPanicActor {
            type Message = ();

            fn handle(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                panic!("panic during shutdown");
            }
        }

        init_test("supervised_actor_stop_prevents_restart_after_panic");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let restart_count = Arc::new(AtomicU32::new(0));
        let rc = Arc::clone(&restart_count);
        let strategy = crate::supervision::SupervisionStrategy::Restart(
            crate::supervision::RestartConfig::new(3, Duration::from_secs(60))
                .with_backoff(crate::supervision::BackoffStrategy::None),
        );

        let (mut handle, stored) = scope
            .spawn_supervised_actor(
                &mut runtime.state,
                &cx,
                move || {
                    rc.fetch_add(1, Ordering::Relaxed);
                    StopThenPanicActor
                },
                strategy,
                8,
            )
            .expect("spawn supervised actor");
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        handle.try_send(()).expect("queue panic message");
        handle.stop();

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_quiescent();

        assert_eq!(
            restart_count.load(Ordering::SeqCst),
            1,
            "explicit stop must suppress supervised restarts"
        );

        let join = futures_lite::future::block_on(handle.join(&cx));
        match join {
            Err(JoinError::Panicked(payload)) => {
                assert_eq!(
                    payload.message(),
                    "panic during shutdown",
                    "shutdown panic should surface without restarting"
                );
            }
            other => panic!("expected shutdown panic without restart, got {other:?}"),
        }

        crate::test_complete!("supervised_actor_stop_prevents_restart_after_panic");
    }

    #[test]
    fn supervised_actor_stop_during_restart_backoff_prevents_new_instance() {
        use std::sync::atomic::AtomicU32;

        #[derive(Debug)]
        struct DelayedRestartActor {
            starts: Arc<AtomicU32>,
        }

        impl Actor for DelayedRestartActor {
            type Message = ();

            fn on_start(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let starts = Arc::clone(&self.starts);
                Box::pin(async move {
                    starts.fetch_add(1, Ordering::Relaxed);
                })
            }

            fn handle(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                panic!("panic before delayed restart");
            }
        }

        init_test("supervised_actor_stop_during_restart_backoff_prevents_new_instance");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let factory_count = Arc::new(AtomicU32::new(0));
        let starts = Arc::new(AtomicU32::new(0));
        let fc = Arc::clone(&factory_count);
        let starts_for_factory = Arc::clone(&starts);
        let strategy = crate::supervision::SupervisionStrategy::Restart(
            crate::supervision::RestartConfig::new(3, Duration::from_secs(60)).with_backoff(
                crate::supervision::BackoffStrategy::Fixed(Duration::from_secs(5)),
            ),
        );

        let (mut handle, stored) = scope
            .spawn_supervised_actor(
                &mut runtime.state,
                &cx,
                move || {
                    fc.fetch_add(1, Ordering::Relaxed);
                    DelayedRestartActor {
                        starts: Arc::clone(&starts_for_factory),
                    }
                },
                strategy,
                8,
            )
            .expect("spawn supervised actor");
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        handle.try_send(()).expect("queue panic message");

        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_idle();
        assert_eq!(
            runtime.pending_timer_count(),
            1,
            "supervised actor should be waiting on restart backoff"
        );

        handle.stop();
        let report = runtime.run_with_auto_advance();

        assert!(
            matches!(
                report.termination,
                crate::lab::AutoAdvanceTermination::Quiescent
            ),
            "runtime should quiesce after stop suppresses restart: {report:?}"
        );
        assert_eq!(
            factory_count.load(Ordering::SeqCst),
            1,
            "graceful stop during backoff must prevent a replacement actor from being constructed"
        );
        assert_eq!(
            starts.load(Ordering::SeqCst),
            1,
            "graceful stop during backoff must prevent restarted actor lifecycle hooks from running"
        );

        let join = futures_lite::future::block_on(handle.join(&cx));
        match join {
            Err(JoinError::Panicked(payload)) => {
                assert_eq!(
                    payload.message(),
                    "panic before delayed restart",
                    "original panic should surface when restart is suppressed"
                );
            }
            other => panic!(
                "expected original panic when stop suppresses delayed restart, got {other:?}"
            ),
        }

        crate::test_complete!("supervised_actor_stop_during_restart_backoff_prevents_new_instance");
    }

    /// A stop during a supervised restart backoff ends the backoff at once:
    /// the actor finishes without waiting for the backoff timer.
    #[test]
    fn supervised_actor_stop_ends_the_restart_backoff_without_waiting_for_it() {
        use std::sync::atomic::AtomicU32;

        #[derive(Debug)]
        struct CrashingActor;

        impl Actor for CrashingActor {
            type Message = ();

            fn handle(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                panic!("panic before delayed restart");
            }
        }

        init_test("supervised_actor_stop_ends_the_restart_backoff_without_waiting_for_it");
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);
        let factory_count = Arc::new(AtomicU32::new(0));
        let fc = Arc::clone(&factory_count);
        let strategy = crate::supervision::SupervisionStrategy::Restart(
            crate::supervision::RestartConfig::new(3, Duration::from_secs(60)).with_backoff(
                crate::supervision::BackoffStrategy::Fixed(Duration::from_secs(3600)),
            ),
        );
        let (mut handle, stored) = scope
            .spawn_supervised_actor(
                &mut runtime.state,
                &cx,
                move || {
                    fc.fetch_add(1, Ordering::Relaxed);
                    CrashingActor
                },
                strategy,
                8,
            )
            .expect("spawn supervised actor");
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);
        handle.try_send(()).expect("queue panic message");
        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_idle();
        assert!(
            !handle.is_finished(),
            "the actor waits out its restart backoff"
        );

        // No virtual time passes: only the stop can end the hour-long backoff.
        handle.stop();
        runtime.run_until_idle();
        assert!(
            handle.is_finished(),
            "the stop ends the backoff instead of waiting for its timer"
        );
        assert_eq!(
            factory_count.load(Ordering::SeqCst),
            1,
            "the stop suppresses the restart"
        );
        match futures_lite::future::block_on(handle.join(&cx)) {
            Err(JoinError::Panicked(payload)) => assert_eq!(
                payload.message(),
                "panic before delayed restart",
                "the original panic surfaces when the stop suppresses the restart"
            ),
            other => panic!("expected the original panic, got {other:?}"),
        }

        crate::test_complete!(
            "supervised_actor_stop_ends_the_restart_backoff_without_waiting_for_it"
        );
    }

    #[test]
    fn spawn_actor_panic_surfaces_as_task_outcome() {
        init_test("spawn_actor_panic_surfaces_as_task_outcome");

        #[derive(Debug)]
        struct PanicActor;

        impl Actor for PanicActor {
            type Message = ();

            fn handle(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                panic!("actor boom");
            }
        }

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (mut handle, mut stored) = scope
            .spawn_actor(&mut state, &cx, PanicActor, 8)
            .expect("spawn actor");
        handle.try_send(()).expect("queue panic message");

        let wake_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let waker = terminal_state_waker(Arc::clone(&handle.state), Arc::clone(&wake_count));
        let mut poll_cx = Context::from_waker(&waker);
        let join = std::pin::pin!(handle.join(&cx));
        let mut join = join;
        assert!(matches!(join.as_mut().poll(&mut poll_cx), Poll::Pending));

        match stored.poll(&mut poll_cx) {
            Poll::Ready(Outcome::Panicked(payload)) => {
                assert_eq!(payload.message(), "actor boom", "panic payload preserved");
            }
            other => panic!("panicking actor task must return Outcome::Panicked: {other:?}"),
        }
        assert_eq!(wake_count.load(Ordering::Relaxed), 1);

        match join.as_mut().poll(&mut poll_cx) {
            Poll::Ready(Err(JoinError::Panicked(payload))) => {
                assert_eq!(
                    payload.message(),
                    "actor boom",
                    "join preserves panic payload"
                );
            }
            other => panic!("join must surface actor panic: {other:?}"),
        }

        crate::test_complete!("spawn_actor_panic_surfaces_as_task_outcome");
    }

    #[test]
    fn spawn_supervised_actor_panic_surfaces_as_task_outcome() {
        init_test("spawn_supervised_actor_panic_surfaces_as_task_outcome");

        #[derive(Debug)]
        struct PanicActor;

        impl Actor for PanicActor {
            type Message = ();

            fn handle(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                panic!("supervised actor boom");
            }
        }

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (mut handle, mut stored) = scope
            .spawn_supervised_actor(
                &mut state,
                &cx,
                || PanicActor,
                crate::supervision::SupervisionStrategy::Stop,
                8,
            )
            .expect("spawn supervised actor");
        handle.try_send(()).expect("queue panic message");

        let wake_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let waker = terminal_state_waker(Arc::clone(&handle.state), Arc::clone(&wake_count));
        let mut poll_cx = Context::from_waker(&waker);
        let join = std::pin::pin!(handle.join(&cx));
        let mut join = join;
        assert!(matches!(join.as_mut().poll(&mut poll_cx), Poll::Pending));

        match stored.poll(&mut poll_cx) {
            Poll::Ready(Outcome::Panicked(payload)) => {
                assert_eq!(
                    payload.message(),
                    "supervised actor boom",
                    "panic payload preserved"
                );
            }
            other => {
                panic!("panicking supervised actor task must return Outcome::Panicked: {other:?}")
            }
        }
        assert_eq!(wake_count.load(Ordering::Relaxed), 1);

        match join.as_mut().poll(&mut poll_cx) {
            Poll::Ready(Err(JoinError::Panicked(payload))) => {
                assert_eq!(
                    payload.message(),
                    "supervised actor boom",
                    "join preserves panic payload"
                );
            }
            other => panic!("join must surface supervised actor panic: {other:?}"),
        }

        crate::test_complete!("spawn_supervised_actor_panic_surfaces_as_task_outcome");
    }

    // br-asupersync-pk44qd S2: a supervised actor that crashed left its other
    // buffered messages in the mailbox, and they dropped with the receiver when
    // the task ended. A message whose destructor panics replaced the task's
    // outcome with that panic (and two of them aborted the process).
    #[test]
    fn a_panicking_buffered_message_does_not_replace_a_supervised_crash() {
        init_test("a_panicking_buffered_message_does_not_replace_a_supervised_crash");

        #[derive(Debug)]
        struct PanicsWhenDropped;
        impl Drop for PanicsWhenDropped {
            fn drop(&mut self) {
                panic!("buffered message destructor");
            }
        }
        #[derive(Debug)]
        enum Msg {
            Crash,
            Leftover(#[allow(dead_code)] PanicsWhenDropped),
        }
        struct CrashActor;
        impl Actor for CrashActor {
            type Message = Msg;

            fn handle(
                &mut self,
                _cx: &Cx,
                msg: Msg,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                if matches!(msg, Msg::Crash) {
                    panic!("supervised actor boom");
                }
                Box::pin(async {})
            }
        }

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);
        let (handle, mut stored) = scope
            .spawn_supervised_actor(
                &mut state,
                &cx,
                || CrashActor,
                crate::supervision::SupervisionStrategy::Stop,
                8,
            )
            .expect("spawn supervised actor");
        handle.try_send(Msg::Crash).expect("queue the crash");
        handle
            .try_send(Msg::Leftover(PanicsWhenDropped))
            .expect("queue a message the crash leaves behind");

        let mut poll_cx = Context::from_waker(Waker::noop());
        let polled =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stored.poll(&mut poll_cx)));
        match polled {
            Ok(Poll::Ready(Outcome::Panicked(payload))) => assert_eq!(
                payload.message(),
                "supervised actor boom",
                "the crash stays the task's outcome"
            ),
            Ok(other) => panic!("expected the crash as the outcome: {other:?}"),
            Err(_) => panic!("a buffered message's destructor panic escaped the actor task"),
        }
        crate::test_complete!("a_panicking_buffered_message_does_not_replace_a_supervised_crash");
    }

    /// A contained destructor panic (an unresolved obligation's ASUP-E101, for
    /// one) must still be visible: it is logged at error level with its message.
    #[cfg(feature = "tracing-integration")]
    #[test]
    fn a_contained_buffered_message_drop_panic_is_logged() {
        #[derive(Clone, Default)]
        struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("capture lock").extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        struct PanicOnDrop;
        impl Drop for PanicOnDrop {
            fn drop(&mut self) {
                panic!("buffered message destructor");
            }
        }

        let capture = Capture::default();
        let writer = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let dropped_cleanly =
            tracing::subscriber::with_default(subscriber, || discard_contained(PanicOnDrop));
        assert!(!dropped_cleanly, "the destructor panicked");
        let log =
            String::from_utf8(capture.0.lock().expect("capture lock").clone()).expect("utf-8 log");
        assert!(
            log.contains("panicked while being dropped")
                && log.contains("buffered message destructor"),
            "the contained panic is logged with its message: {log:?}"
        );
    }

    #[test]
    fn supervised_restart_factory_panic_reaches_join_and_marks_stopped() {
        use std::sync::atomic::AtomicU32;

        init_test("supervised_restart_factory_panic_reaches_join_and_marks_stopped");

        #[derive(Debug)]
        struct PanicActor;

        impl Actor for PanicActor {
            type Message = ();

            fn handle(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                panic!("actor panic before restart factory");
            }
        }

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);
        let factory_calls = Arc::new(AtomicU32::new(0));
        let calls = Arc::clone(&factory_calls);

        let (mut handle, mut stored) = scope
            .spawn_supervised_actor(
                &mut state,
                &cx,
                move || {
                    let attempt = calls.fetch_add(1, Ordering::Relaxed);
                    if attempt == 0 {
                        PanicActor
                    } else {
                        panic!("restart factory boom");
                    }
                },
                crate::supervision::SupervisionStrategy::Restart(
                    crate::supervision::RestartConfig::new(1, Duration::from_secs(60))
                        .with_backoff(crate::supervision::BackoffStrategy::None),
                ),
                8,
            )
            .expect("spawn supervised actor");
        assert_eq!(
            factory_calls.load(Ordering::Relaxed),
            0,
            "supervised actor factory must stay lazy until the stored task's first poll"
        );
        handle.try_send(()).expect("queue panic message");

        let actor_ref = handle.sender();
        let wake_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let waker = terminal_state_waker(Arc::clone(&handle.state), Arc::clone(&wake_count));
        let mut poll_cx = Context::from_waker(&waker);
        let join = std::pin::pin!(handle.join(&cx));
        let mut join = join;
        assert!(matches!(join.as_mut().poll(&mut poll_cx), Poll::Pending));

        match stored.poll(&mut poll_cx) {
            Poll::Ready(Outcome::Panicked(payload)) => {
                assert_eq!(payload.message(), "restart factory boom");
            }
            other => panic!("restart factory panic must terminate the task: {other:?}"),
        }

        assert_eq!(factory_calls.load(Ordering::Relaxed), 2);
        assert_eq!(wake_count.load(Ordering::Relaxed), 1);
        assert!(
            !actor_ref.is_alive(),
            "restart factory panic must publish the terminal actor state"
        );

        match join.as_mut().poll(&mut poll_cx) {
            Poll::Ready(Err(JoinError::Panicked(payload))) => {
                assert_eq!(payload.message(), "restart factory boom");
            }
            other => panic!("join must preserve the restart factory panic: {other:?}"),
        }

        crate::test_complete!("supervised_restart_factory_panic_reaches_join_and_marks_stopped");
    }

    #[test]
    fn supervised_restart_delay_honors_cancellation() {
        init_test("supervised_restart_delay_honors_cancellation");

        let cx = Cx::for_testing();
        cx.cancel_fast(crate::types::CancelKind::User);

        let state = ActorStateCell::new(ActorState::Running);
        let mut delay = std::pin::pin!(wait_supervised_restart_delay(
            &cx,
            &state,
            std::time::Duration::from_secs(60),
        ));
        let first_poll =
            futures_lite::future::block_on(futures_lite::future::poll_once(&mut delay));

        match first_poll {
            Some(Outcome::Err(JoinError::Cancelled(reason))) => {
                assert_eq!(reason.kind, crate::types::CancelKind::User);
            }
            other => panic!("expected immediate cancellation, got {other:?}"),
        }

        crate::test_complete!("supervised_restart_delay_honors_cancellation");
    }

    /// E2E: Deterministic replay — same seed produces same actor execution.
    #[test]
    fn actor_deterministic_replay() {
        fn run_scenario(seed: u64) -> u64 {
            let config = crate::lab::LabConfig::new(seed);
            let mut runtime = crate::lab::LabRuntime::new(config);
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let cx: Cx = Cx::for_testing();
            let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

            let (on_stop_count, started, stopped) = observable_state();
            let actor = ObservableCounter::new(on_stop_count.clone(), started, stopped);

            let (handle, stored) = scope
                .spawn_actor(&mut runtime.state, &cx, actor, 32)
                .unwrap();
            let task_id = handle.task_id();
            runtime.state.store_spawned_task(task_id, stored);

            for i in 1..=10 {
                handle.try_send(i).unwrap();
            }
            drop(handle);

            runtime.scheduler.lock().schedule(task_id, 0);
            runtime.run_until_quiescent();

            on_stop_count.load(Ordering::SeqCst)
        }

        init_test("actor_deterministic_replay");

        // Run the same scenario twice with the same seed
        let result1 = run_scenario(0xDEAD_BEEF);
        let result2 = run_scenario(0xDEAD_BEEF);

        assert_eq!(
            result1, result2,
            "deterministic replay: same seed → same result"
        );
        assert_eq!(result1, 55, "sum of 1..=10");

        crate::test_complete!("actor_deterministic_replay");
    }

    // ---- ActorContext Tests ----

    #[test]
    fn actor_context_self_reference() {
        init_test("actor_context_self_reference");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_actor(&mut state, &cx, Counter::new(), 32)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        // Create an ActorContext using the handle's sender
        let actor_ref = handle.sender();
        let actor_id = handle.actor_id();
        let ctx: ActorContext<'_, u64> = ActorContext::new(&cx, actor_ref, actor_id, None);

        // Test self_actor_id() - doesn't require Clone
        assert_eq!(ctx.self_actor_id(), actor_id);
        assert_eq!(ctx.actor_id(), actor_id);

        crate::test_complete!("actor_context_self_reference");
    }

    #[test]
    fn actor_context_child_management() {
        init_test("actor_context_child_management");

        let cx: Cx = Cx::for_testing();
        let (sender, _receiver) = mpsc::channel::<u64>(32);
        let actor_id = ActorId::from_task(TaskId::new_for_test(1, 1));
        let actor_ref = ActorRef {
            actor_id,
            sender,
            state: Arc::new(ActorStateCell::new(ActorState::Running)),
        };

        let mut ctx = ActorContext::new(&cx, actor_ref, actor_id, None);

        // Initially no children
        assert!(!ctx.has_children());
        assert_eq!(ctx.child_count(), 0);
        assert!(ctx.children().is_empty());

        // Register children
        let child1 = ActorId::from_task(TaskId::new_for_test(2, 1));
        let child2 = ActorId::from_task(TaskId::new_for_test(3, 1));

        ctx.register_child(child1);
        assert!(ctx.has_children());
        assert_eq!(ctx.child_count(), 1);

        ctx.register_child(child2);
        assert_eq!(ctx.child_count(), 2);

        // Unregister child
        assert!(ctx.unregister_child(child1));
        assert_eq!(ctx.child_count(), 1);

        // Unregistering non-existent child returns false
        assert!(!ctx.unregister_child(child1));

        crate::test_complete!("actor_context_child_management");
    }

    #[test]
    fn actor_context_stopping() {
        init_test("actor_context_stopping");

        let cx: Cx = Cx::for_testing();
        let (sender, _receiver) = mpsc::channel::<u64>(32);
        let actor_id = ActorId::from_task(TaskId::new_for_test(1, 1));
        let actor_ref = ActorRef {
            actor_id,
            sender,
            state: Arc::new(ActorStateCell::new(ActorState::Running)),
        };

        let mut ctx = ActorContext::new(&cx, actor_ref, actor_id, None);

        // Initially not stopping
        assert!(!ctx.is_stopping());
        assert!(ctx.checkpoint().is_ok());

        // Request stop
        ctx.stop_self();
        assert!(ctx.is_stopping());
        assert!(ctx.checkpoint().is_err());
        assert!(cx.checkpoint().is_ok());
        assert!(ctx.is_cancel_requested());

        crate::test_complete!("actor_context_stopping");
    }

    #[test]
    fn actor_context_parent_none() {
        init_test("actor_context_parent_none");

        let cx: Cx = Cx::for_testing();
        let (sender, _receiver) = mpsc::channel::<u64>(32);
        let actor_id = ActorId::from_task(TaskId::new_for_test(1, 1));
        let actor_ref = ActorRef {
            actor_id,
            sender,
            state: Arc::new(ActorStateCell::new(ActorState::Running)),
        };

        let ctx = ActorContext::new(&cx, actor_ref, actor_id, None);

        // Root actor has no parent
        assert!(!ctx.has_parent());
        assert!(ctx.parent().is_none());

        crate::test_complete!("actor_context_parent_none");
    }

    #[test]
    fn actor_context_cx_delegation() {
        init_test("actor_context_cx_delegation");

        let cx: Cx = Cx::for_testing();
        let (sender, _receiver) = mpsc::channel::<u64>(32);
        let actor_id = ActorId::from_task(TaskId::new_for_test(1, 1));
        let actor_ref = ActorRef {
            actor_id,
            sender,
            state: Arc::new(ActorStateCell::new(ActorState::Running)),
        };

        let ctx = ActorContext::new(&cx, actor_ref, actor_id, None);

        // Test Cx delegation via Deref
        let _budget = ctx.budget();
        ctx.trace("test_event");

        // Test cx() accessor
        let _cx_ref = ctx.cx();

        crate::test_complete!("actor_context_cx_delegation");
    }

    #[test]
    fn actor_context_debug() {
        init_test("actor_context_debug");

        let cx: Cx = Cx::for_testing();
        let (sender, _receiver) = mpsc::channel::<u64>(32);
        let actor_id = ActorId::from_task(TaskId::new_for_test(1, 1));
        let actor_ref = ActorRef {
            actor_id,
            sender,
            state: Arc::new(ActorStateCell::new(ActorState::Running)),
        };

        let ctx = ActorContext::new(&cx, actor_ref, actor_id, None);

        // Debug formatting should work
        let debug_str = format!("{ctx:?}");
        assert!(debug_str.contains("ActorContext"));
        assert!(debug_str.contains("actor_id"));

        crate::test_complete!("actor_context_debug");
    }

    // ---- Invariant Tests ----

    /// Invariant: `ActorStateCell` encode/decode roundtrips correctly for all
    /// valid states, and unknown u8 values map to `Stopped` (fail-safe).
    #[test]
    fn actor_state_cell_encode_decode_roundtrip() {
        init_test("actor_state_cell_encode_decode_roundtrip");

        let states = [
            ActorState::Created,
            ActorState::Running,
            ActorState::Stopping,
            ActorState::Stopped,
        ];

        for &state in &states {
            let cell = ActorStateCell::new(state);
            let loaded = cell.load();
            crate::assert_with_log!(loaded == state, "roundtrip", state, loaded);
        }

        // Unknown values (4+) should map to Stopped (fail-safe).
        for raw in 4_u8..=10 {
            let decoded = ActorStateCell::decode(raw);
            let is_stopped = decoded == ActorState::Stopped;
            crate::assert_with_log!(is_stopped, "unknown u8 -> Stopped", true, is_stopped);
        }

        crate::test_complete!("actor_state_cell_encode_decode_roundtrip");
    }

    /// Invariant: `MailboxConfig::default()` has documented capacity and
    /// backpressure enabled.
    #[test]
    fn mailbox_config_defaults() {
        init_test("mailbox_config_defaults");

        let config = MailboxConfig::default();
        crate::assert_with_log!(
            config.capacity == DEFAULT_MAILBOX_CAPACITY,
            "default capacity",
            DEFAULT_MAILBOX_CAPACITY,
            config.capacity
        );
        crate::assert_with_log!(
            config.backpressure,
            "backpressure enabled by default",
            true,
            config.backpressure
        );

        let custom = MailboxConfig::with_capacity(8);
        crate::assert_with_log!(
            custom.capacity == 8,
            "custom capacity",
            8usize,
            custom.capacity
        );
        crate::assert_with_log!(
            custom.backpressure,
            "with_capacity enables backpressure",
            true,
            custom.backpressure
        );

        crate::test_complete!("mailbox_config_defaults");
    }

    /// Invariant: `try_send` on a full mailbox returns an error without
    /// blocking, and the message is recoverable from the error.
    #[test]
    fn actor_try_send_full_mailbox_returns_error() {
        init_test("actor_try_send_full_mailbox_returns_error");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        // Create actor with capacity=2 mailbox.
        let (handle, stored) = scope
            .spawn_actor(&mut state, &cx, Counter::new(), 2)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        // Fill the mailbox.
        let ok1 = handle.try_send(1).is_ok();
        crate::assert_with_log!(ok1, "first send ok", true, ok1);
        let ok2 = handle.try_send(2).is_ok();
        crate::assert_with_log!(ok2, "second send ok", true, ok2);

        // Third send should fail — mailbox full.
        let result = handle.try_send(3);
        let is_full = result.is_err();
        crate::assert_with_log!(is_full, "third send fails (full)", true, is_full);

        crate::test_complete!("actor_try_send_full_mailbox_returns_error");
    }

    /// Invariant: `ActorContext` with a parent supervisor set exposes it
    /// and reports `has_parent() == true`.
    #[test]
    fn actor_context_with_parent_supervisor() {
        init_test("actor_context_with_parent_supervisor");

        let cx: Cx = Cx::for_testing();

        // Create parent supervisor channel.
        let (parent_sender, _parent_receiver) = mpsc::channel::<SupervisorMessage>(8);
        let parent_id = ActorId::from_task(TaskId::new_for_test(10, 1));
        let parent_ref = ActorRef {
            actor_id: parent_id,
            sender: parent_sender,
            state: Arc::new(ActorStateCell::new(ActorState::Running)),
        };

        // Create child actor context with parent.
        let (child_sender, _child_receiver) = mpsc::channel::<u64>(32);
        let child_id = ActorId::from_task(TaskId::new_for_test(20, 1));
        let child_ref = ActorRef {
            actor_id: child_id,
            sender: child_sender,
            state: Arc::new(ActorStateCell::new(ActorState::Running)),
        };

        let ctx = ActorContext::new(&cx, child_ref, child_id, Some(parent_ref));

        let has_parent = ctx.has_parent();
        crate::assert_with_log!(has_parent, "has parent", true, has_parent);

        let parent = ctx.parent().expect("parent should be Some");
        let parent_id_matches = parent.actor_id() == parent_id;
        crate::assert_with_log!(
            parent_id_matches,
            "parent id matches",
            true,
            parent_id_matches
        );

        crate::test_complete!("actor_context_with_parent_supervisor");
    }

    // ---- Pure Data Type Tests (no runtime needed) ----

    #[test]
    fn actor_id_debug_format() {
        let id = ActorId::from_task(TaskId::new_for_test(5, 3));
        let dbg = format!("{id:?}");
        assert!(dbg.contains("ActorId"), "{dbg}");
    }

    #[test]
    fn actor_id_display_delegates_to_task_id() {
        let tid = TaskId::new_for_test(7, 2);
        let aid = ActorId::from_task(tid);
        assert_eq!(format!("{aid}"), format!("{tid}"));
    }

    #[test]
    fn actor_id_from_task_roundtrip() {
        let tid = TaskId::new_for_test(3, 1);
        let aid = ActorId::from_task(tid);
        assert_eq!(aid.task_id(), tid);
    }

    #[test]
    fn actor_id_copy_clone() {
        let id = ActorId::from_task(TaskId::new_for_test(1, 1));
        let copied = id; // Copy
        let cloned = id;
        assert_eq!(id, copied);
        assert_eq!(id, cloned);
    }

    #[test]
    fn actor_id_hash_consistency() {
        use crate::util::DetHasher;
        use std::hash::{Hash, Hasher};

        let id1 = ActorId::from_task(TaskId::new_for_test(4, 2));
        let id2 = ActorId::from_task(TaskId::new_for_test(4, 2));
        assert_eq!(id1, id2);

        let mut h1 = DetHasher::default();
        let mut h2 = DetHasher::default();
        id1.hash(&mut h1);
        id2.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish(), "equal IDs must hash equal");
    }

    #[test]
    fn actor_state_debug_all_variants() {
        for (state, expected) in [
            (ActorState::Created, "Created"),
            (ActorState::Running, "Running"),
            (ActorState::Stopping, "Stopping"),
            (ActorState::Stopped, "Stopped"),
        ] {
            let dbg = format!("{state:?}");
            assert_eq!(dbg, expected, "ActorState::{expected}");
        }
    }

    #[test]
    fn actor_state_clone_copy_eq() {
        let s = ActorState::Running;
        let copied = s;
        let cloned = s;
        assert_eq!(s, copied);
        assert_eq!(s, cloned);
    }

    #[test]
    fn actor_state_exhaustive_inequality() {
        let all = [
            ActorState::Created,
            ActorState::Running,
            ActorState::Stopping,
            ActorState::Stopped,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn actor_state_cell_sequential_transitions() {
        let cell = ActorStateCell::new(ActorState::Created);
        assert_eq!(cell.load(), ActorState::Created);

        cell.store(ActorState::Running);
        assert_eq!(cell.load(), ActorState::Running);

        cell.store(ActorState::Stopping);
        assert_eq!(cell.load(), ActorState::Stopping);

        cell.store(ActorState::Stopped);
        assert_eq!(cell.load(), ActorState::Stopped);
    }

    #[test]
    fn supervised_restart_commit_preserves_a_winning_stop() {
        let restart_wins = ActorStateCell::new(ActorState::Running);
        assert!(try_commit_supervised_restart(&restart_wins));
        assert_eq!(restart_wins.load(), ActorState::Created);

        let stop_wins = ActorStateCell::new(ActorState::Running);
        stop_wins.store(ActorState::Stopping);
        assert!(
            !try_commit_supervised_restart(&stop_wins),
            "restart commit must fail after a concurrent stop linearizes"
        );
        assert_eq!(
            stop_wins.load(),
            ActorState::Stopping,
            "failed restart commit must not overwrite the stop request"
        );
    }

    #[test]
    fn supervisor_message_debug_child_failed() {
        let msg = SupervisorMessage::ChildFailed {
            child_id: ActorId::from_task(TaskId::new_for_test(1, 1)),
            reason: "panicked".to_string(),
        };
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("ChildFailed"), "{dbg}");
        assert!(dbg.contains("panicked"), "{dbg}");
    }

    #[test]
    fn supervisor_message_debug_child_stopped() {
        let msg = SupervisorMessage::ChildStopped {
            child_id: ActorId::from_task(TaskId::new_for_test(2, 1)),
        };
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("ChildStopped"), "{dbg}");
    }

    #[test]
    fn supervisor_message_clone() {
        let msg = SupervisorMessage::ChildFailed {
            child_id: ActorId::from_task(TaskId::new_for_test(1, 1)),
            reason: "boom".to_string(),
        };
        let cloned = msg.clone();
        let (a, b) = (format!("{msg:?}"), format!("{cloned:?}"));
        assert_eq!(a, b);
    }

    #[test]
    fn supervised_outcome_debug_all_variants() {
        let variants: Vec<SupervisedOutcome> = vec![
            SupervisedOutcome::Stopped,
            SupervisedOutcome::RestartBudgetExhausted { total_restarts: 5 },
            SupervisedOutcome::Escalated,
        ];
        for v in &variants {
            let dbg = format!("{v:?}");
            assert!(!dbg.is_empty());
        }
        assert!(format!("{variants0:?}", variants0 = variants[0]).contains("Stopped"));
        assert!(format!("{variants1:?}", variants1 = variants[1]).contains('5'));
        assert!(format!("{variants2:?}", variants2 = variants[2]).contains("Escalated"));
    }

    #[test]
    fn mailbox_config_debug_clone_copy() {
        let cfg = MailboxConfig::default();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("MailboxConfig"), "{dbg}");
        assert!(dbg.contains("64"), "{dbg}");

        let copied = cfg;
        let cloned = cfg;
        assert_eq!(copied.capacity, cfg.capacity);
        assert_eq!(cloned.backpressure, cfg.backpressure);
    }

    #[test]
    fn mailbox_config_zero_capacity() {
        let cfg = MailboxConfig::with_capacity(0);
        assert_eq!(cfg.capacity, 0);
        assert!(cfg.backpressure);
    }

    #[test]
    fn mailbox_config_max_capacity() {
        let cfg = MailboxConfig::with_capacity(usize::MAX);
        assert_eq!(cfg.capacity, usize::MAX);
    }

    #[test]
    fn default_mailbox_capacity_is_64() {
        assert_eq!(DEFAULT_MAILBOX_CAPACITY, 64);
    }

    #[test]
    fn actor_context_duplicate_child_registration() {
        let cx: Cx = Cx::for_testing();
        let (sender, _receiver) = mpsc::channel::<u64>(32);
        let actor_id = ActorId::from_task(TaskId::new_for_test(1, 1));
        let actor_ref = ActorRef {
            actor_id,
            sender,
            state: Arc::new(ActorStateCell::new(ActorState::Running)),
        };

        let mut ctx = ActorContext::new(&cx, actor_ref, actor_id, None);
        let child = ActorId::from_task(TaskId::new_for_test(2, 1));

        ctx.register_child(child);
        ctx.register_child(child); // duplicate
        assert_eq!(ctx.child_count(), 2, "register_child does not dedup");

        // Unregister removes first occurrence
        assert!(ctx.unregister_child(child));
        assert_eq!(ctx.child_count(), 1, "one copy remains");
        assert!(ctx.unregister_child(child));
        assert_eq!(ctx.child_count(), 0);
        assert!(!ctx.unregister_child(child), "nothing left to remove");
    }

    #[test]
    fn actor_context_stop_self_is_idempotent() {
        let cx: Cx = Cx::for_testing();
        let (sender, _receiver) = mpsc::channel::<u64>(32);
        let actor_id = ActorId::from_task(TaskId::new_for_test(1, 1));
        let actor_ref = ActorRef {
            actor_id,
            sender,
            state: Arc::new(ActorStateCell::new(ActorState::Running)),
        };

        let mut ctx = ActorContext::new(&cx, actor_ref, actor_id, None);
        ctx.stop_self();
        assert!(ctx.is_stopping());
        ctx.stop_self(); // idempotent
        assert!(ctx.is_stopping());
    }

    #[test]
    fn actor_context_self_ref_returns_working_ref() {
        let cx: Cx = Cx::for_testing();
        let (sender, _receiver) = mpsc::channel::<u64>(32);
        let actor_id = ActorId::from_task(TaskId::new_for_test(1, 1));
        let actor_ref = ActorRef {
            actor_id,
            sender,
            state: Arc::new(ActorStateCell::new(ActorState::Running)),
        };

        let ctx = ActorContext::new(&cx, actor_ref, actor_id, None);
        let self_ref = ctx.self_ref();
        assert_eq!(self_ref.actor_id(), actor_id);
        assert!(self_ref.is_alive());
    }

    #[test]
    fn actor_context_deadline_reflects_budget() {
        let cx: Cx = Cx::for_testing();
        let (sender, _receiver) = mpsc::channel::<u64>(32);
        let actor_id = ActorId::from_task(TaskId::new_for_test(1, 1));
        let actor_ref = ActorRef {
            actor_id,
            sender,
            state: Arc::new(ActorStateCell::new(ActorState::Running)),
        };

        let ctx = ActorContext::new(&cx, actor_ref, actor_id, None);
        // for_testing() Cx has INFINITE budget, which has no deadline
        assert!(ctx.deadline().is_none());
    }

    #[test]
    fn actor_handle_debug() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_actor(&mut state, &cx, Counter::new(), 32)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        let dbg = format!("{handle:?}");
        assert!(dbg.contains("ActorHandle"), "{dbg}");
    }

    #[test]
    fn actor_handle_second_join_fails_closed() {
        init_test("actor_handle_second_join_fails_closed");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (mut handle, stored) = scope
            .spawn_actor(&mut runtime.state, &cx, Counter::new(), 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        handle.stop();
        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_quiescent();
        assert!(handle.is_finished(), "stopped actor should report finished");

        let final_state = futures_lite::future::block_on(handle.join(&cx)).expect("first join");
        assert_eq!(final_state.count, 0, "join should return final actor state");

        let second = futures_lite::future::block_on(handle.join(&cx));
        assert!(
            matches!(second, Err(JoinError::PolledAfterCompletion)),
            "second join must fail closed, got {second:?}"
        );

        crate::test_complete!("actor_handle_second_join_fails_closed");
    }

    #[test]
    fn actor_join_future_closed_inner_maps_to_cancelled_reason() {
        init_test("actor_join_future_closed_inner_maps_to_cancelled_reason");

        let (result_tx, mut result_rx) =
            crate::channel::oneshot::channel::<Result<Counter, JoinError>>();
        drop(result_tx);
        let mut terminal_state = false;
        let poll_result = {
            let mut join = std::pin::pin!(actor_join_future_from_receiver::<Counter>(
                &mut result_rx,
                &mut terminal_state,
            ));
            let waker = counting_waker(Arc::new(std::sync::atomic::AtomicUsize::new(0)));
            let mut poll_cx = Context::from_waker(&waker);
            join.as_mut().poll(&mut poll_cx)
        };

        match poll_result {
            Poll::Ready(Err(JoinError::Cancelled(reason))) => {
                assert_eq!(reason.kind, crate::types::CancelKind::User);
                assert_eq!(
                    reason.message.as_deref(),
                    Some("join channel closed"),
                    "closed inner oneshot should surface the explicit join-channel reason"
                );
            }
            other => panic!("closed inner join future must map to Cancelled, got {other:?}"),
        }

        assert!(
            terminal_state,
            "closed join future should mark terminal state"
        );
        crate::test_complete!("actor_join_future_closed_inner_maps_to_cancelled_reason");
    }

    #[test]
    fn actor_join_future_repoll_fails_before_inner_polled_after_completion() {
        init_test("actor_join_future_repoll_fails_before_inner_polled_after_completion");

        let (result_tx, mut result_rx) =
            crate::channel::oneshot::channel::<Result<Counter, JoinError>>();
        let cx: Cx = Cx::for_testing();
        result_tx
            .send(&cx, Ok(Counter::new()))
            .expect("seed join result");
        let mut terminal_state = false;
        let (first_poll, second_poll) = {
            let mut join = std::pin::pin!(actor_join_future_from_receiver::<Counter>(
                &mut result_rx,
                &mut terminal_state,
            ));
            let waker = counting_waker(Arc::new(std::sync::atomic::AtomicUsize::new(0)));
            let mut poll_cx = Context::from_waker(&waker);
            let first_poll = join.as_mut().poll(&mut poll_cx);
            let second_poll = join.as_mut().poll(&mut poll_cx);
            (first_poll, second_poll)
        };

        match first_poll {
            Poll::Ready(Ok(actor)) => {
                assert_eq!(actor.count, 0, "seeded actor state should round-trip");
            }
            other => panic!("first poll should return actor state, got {other:?}"),
        }

        assert!(terminal_state, "successful join should mark terminal state");

        match second_poll {
            Poll::Ready(Err(JoinError::PolledAfterCompletion)) => {}
            other => panic!(
                "re-poll should fail closed before the inner oneshot can return PolledAfterCompletion, got {other:?}"
            ),
        }

        crate::test_complete!(
            "actor_join_future_repoll_fails_before_inner_polled_after_completion"
        );
    }

    #[test]
    fn actor_ref_debug() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_actor(&mut state, &cx, Counter::new(), 32)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        let actor_ref = handle.sender();
        let dbg = format!("{actor_ref:?}");
        assert!(dbg.contains("ActorRef"), "{dbg}");
    }

    #[test]
    fn actor_state_cell_debug() {
        let cell = ActorStateCell::new(ActorState::Running);
        let dbg = format!("{cell:?}");
        assert!(dbg.contains("ActorStateCell"), "{dbg}");
    }

    #[test]
    fn actor_id_clone_copy_eq_hash() {
        use std::collections::HashSet;

        let id = ActorId::from_task(TaskId::new_for_test(1, 0));
        let dbg = format!("{id:?}");
        assert!(dbg.contains("ActorId"));

        let id2 = id;
        assert_eq!(id, id2);

        // Copy
        let id3 = id;
        assert_eq!(id, id3);

        // Hash
        let mut set = HashSet::new();
        set.insert(id);
        set.insert(ActorId::from_task(TaskId::new_for_test(2, 0)));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn actor_state_debug_clone_copy_eq() {
        let s = ActorState::Running;
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Running"));

        let s2 = s;
        assert_eq!(s, s2);

        let s3 = s;
        assert_eq!(s, s3);

        assert_ne!(ActorState::Created, ActorState::Stopped);
    }

    #[test]
    fn mailbox_config_debug_clone_copy_default() {
        let c = MailboxConfig::default();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("MailboxConfig"));

        let c2 = c;
        assert_eq!(c2.capacity, c.capacity);
        assert_eq!(c2.backpressure, c.backpressure);

        // Copy
        let c3 = c;
        assert_eq!(c3.capacity, c.capacity);
    }

    #[test]
    #[should_panic(expected = "channel capacity must be non-zero")]
    fn spawn_actor_zero_capacity_panics() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);
        let _ = scope.spawn_actor(&mut state, &cx, Counter::new(), 0);
    }

    #[test]
    fn abort_with_panic_on_drop_messages_is_contained_and_runs_on_stop() {
        init_test("abort_with_panic_on_drop_messages_is_contained_and_runs_on_stop");

        #[derive(Debug)]
        struct PanicDropMsg(#[allow(dead_code)] u32);
        impl Drop for PanicDropMsg {
            fn drop(&mut self) {
                panic!("intentional panic on message drop");
            }
        }

        struct DropPanicActor {
            stopped: Arc<parking_lot::Mutex<bool>>,
        }

        impl Actor for DropPanicActor {
            type Message = PanicDropMsg;

            fn handle(
                &mut self,
                _cx: &Cx,
                _msg: Self::Message,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                Box::pin(async {})
            }

            fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                *self.stopped.lock() = true;
                Box::pin(async {})
            }
        }

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx: Cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let stopped = Arc::new(parking_lot::Mutex::new(false));
        let actor = DropPanicActor {
            stopped: Arc::clone(&stopped),
        };

        let (handle, mut stored) = scope
            .spawn_actor(&mut state, &cx, actor, 8)
            .expect("spawn actor");

        // Enqueue multiple panic-on-drop messages
        handle.try_send(PanicDropMsg(1)).expect("send msg 1");
        handle.try_send(PanicDropMsg(2)).expect("send msg 2");

        // Abort the actor
        handle.abort();

        // Run the task: it should safely discard the messages, run on_stop, and finish
        let waker = Waker::noop();
        let mut task_cx = Context::from_waker(waker);
        assert!(
            stored.poll(&mut task_cx).is_ready(),
            "the aborted actor task must finish without an unhandled unwind"
        );

        assert!(
            *stopped.lock(),
            "on_stop must be invoked even when discarded messages panic on drop"
        );

        crate::test_complete!("abort_with_panic_on_drop_messages_is_contained_and_runs_on_stop");
    }
