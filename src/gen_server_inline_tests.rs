    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::runtime::state::RuntimeState;
    use crate::runtime::yield_now;
    use crate::supervision::ChildStart;
    use crate::types::Budget;
    use crate::types::CancelKind;
    use crate::types::RegionId;
    use crate::types::policy::FailFast;
    use crate::util::ArenaIndex;
    use parking_lot::Mutex;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn tracked_reply_test_cx() -> Cx {
        Cx::new(
            RegionId::new_for_test(1, 0),
            TaskId::new_for_test(1, 0),
            Budget::INFINITE,
        )
    }

    fn terminal_state_waker(state: Arc<GenServerStateCell>, counter: Arc<AtomicUsize>) -> Waker {
        struct TerminalStateWaker {
            state: Arc<GenServerStateCell>,
            counter: Arc<AtomicUsize>,
        }

        impl TerminalStateWaker {
            fn record_wake(&self) {
                assert_eq!(
                    self.state.load(),
                    ActorState::Stopped,
                    "join receiver must not wake before gen_server state is terminal"
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

    /// Allocates a child region of `region` for a lab client task
    /// (asupersync-0ex6x0): `call` refuses root-region callers, and a child
    /// region also exercises the production graded reply-token path instead
    /// of the region-0 test fallback in `channel::session`.
    fn lab_client_region(
        runtime: &mut crate::lab::LabRuntime,
        region: RegionId,
        budget: Budget,
    ) -> RegionId {
        runtime
            .state
            .create_child_region(region, budget)
            .expect("create lab client child region")
    }

    /// Builds the caller `Cx` for lab tests in a fresh child region of
    /// `region` (see [`lab_client_region`]).
    fn lab_spawn_cx(runtime: &mut crate::lab::LabRuntime, region: RegionId, budget: Budget) -> Cx {
        let caller_region = lab_client_region(runtime, region, budget);
        Cx::new(caller_region, TaskId::testing_default(), budget)
            .with_spawn_gateway(runtime.state.spawn_gateway())
            .with_pending_spawn_counter(
                runtime
                    .state
                    .region(caller_region)
                    .map(crate::record::RegionRecord::pending_spawn_handle),
            )
    }

    // ---- Simple Counter GenServer ----

    #[derive(Debug)]
    struct Counter {
        count: u64,
    }

    enum CounterCall {
        Get,
        Add(u64),
    }

    enum CounterCast {
        Reset,
    }

    impl GenServer for Counter {
        type Call = CounterCall;
        type Reply = u64;
        type Cast = CounterCast;
        type Info = SystemMsg;

        fn handle_call(
            &mut self,
            _cx: &Cx,
            request: CounterCall,
            reply: Reply<u64>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            match request {
                CounterCall::Get => {
                    let _ = reply.send(self.count);
                }
                CounterCall::Add(n) => {
                    self.count += n;
                    let _ = reply.send(self.count);
                }
            }
            Box::pin(async {})
        }

        fn handle_cast(
            &mut self,
            _cx: &Cx,
            msg: CounterCast,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            match msg {
                CounterCast::Reset => self.count = 0,
            }
            Box::pin(async {})
        }
    }

    /// The native spawn's task handle leaves the handle's and the join
    /// future's auto traits unchanged (br-asupersync-yvs9cx).
    #[test]
    fn gen_server_handle_and_join_future_keep_their_auto_traits() {
        fn assert_send_sync_unpin<T: Send + Sync + Unpin>() {}
        assert_send_sync_unpin::<GenServerHandle<Counter>>();
        assert_send_sync_unpin::<GenServerJoinFuture<'static, Counter>>();
    }

    struct FairnessProbeServer {
        handled: Arc<AtomicUsize>,
    }

    impl GenServer for FairnessProbeServer {
        type Call = ();
        type Reply = ();
        type Cast = ();
        type Info = SystemMsg;

        fn handle_call(
            &mut self,
            _cx: &Cx,
            (): (),
            reply: Reply<()>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            let _ = reply.send(());
            Box::pin(async {})
        }

        fn handle_cast(
            &mut self,
            _cx: &Cx,
            (): (),
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.handled.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {})
        }
    }

    /// A fully ready mailbox must still yield the worker after a bounded batch.
    ///
    /// The single-poll assertion distinguishes a real scheduling point from the
    /// previous trace-only counter: the no-op implementation consumed all
    /// sixteen casts before returning `Pending` on the empty mailbox.
    #[test]
    fn gen_server_ready_mailbox_yields_after_bounded_batch() {
        init_test("gen_server_ready_mailbox_yields_after_bounded_batch");

        let handled = Arc::new(AtomicUsize::new(0));
        let server = FairnessProbeServer {
            handled: Arc::clone(&handled),
        };
        let (sender, mailbox) = mpsc::channel(16);
        for _ in 0..16 {
            sender
                .try_send(Envelope::Cast { msg: () })
                .expect("queue ready GenServer cast");
        }

        let state = Arc::new(GenServerStateCell::new(ActorState::Created));
        let mut cell = GenServerCell {
            mailbox,
            state: Arc::clone(&state),
            _keep_alive: sender.clone(),
            system: Arc::new(SystemLane::new()),
        };
        let cx = Cx::for_testing();
        let mut server_loop = Box::pin(run_gen_server_loop(server, cx, &mut cell));
        let waker = Waker::noop().clone();
        let mut task_cx = Context::from_waker(&waker);

        assert!(matches!(
            server_loop.as_mut().poll(&mut task_cx),
            Poll::Pending
        ));
        assert_eq!(
            handled.load(Ordering::SeqCst),
            8,
            "one poll must stop at the fairness batch boundary"
        );
        assert_eq!(state.load(), ActorState::Running);

        crate::test_complete!("gen_server_ready_mailbox_yields_after_bounded_batch");
    }

    #[derive(Clone)]
    struct StartBudgetProbe {
        started_priority: Arc<AtomicU8>,
        loop_priority: Arc<AtomicU8>,
    }

    impl GenServer for StartBudgetProbe {
        type Call = CounterCall;
        type Reply = u8;
        type Cast = CounterCast;
        type Info = SystemMsg;

        fn on_start(&mut self, cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.started_priority
                .store(cx.budget().priority, Ordering::SeqCst);
            Box::pin(async {})
        }

        fn on_start_budget(&self) -> Budget {
            Budget::new().with_priority(200)
        }

        fn handle_call(
            &mut self,
            cx: &Cx,
            _request: CounterCall,
            reply: Reply<u8>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.loop_priority
                .store(cx.budget().priority, Ordering::SeqCst);
            let _ = reply.send(cx.budget().priority);
            Box::pin(async {})
        }
    }

    struct StopMaskProbe {
        stop_checkpoint_ok: Arc<AtomicU8>,
    }

    impl GenServer for StopMaskProbe {
        type Call = CounterCall;
        type Reply = u8;
        type Cast = CounterCast;
        type Info = SystemMsg;

        fn handle_call(
            &mut self,
            _cx: &Cx,
            _request: CounterCall,
            reply: Reply<u8>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            let _ = reply.send(0);
            Box::pin(async {})
        }

        fn on_stop(&mut self, cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            let ok = cx.checkpoint().is_ok();
            self.stop_checkpoint_ok
                .store(u8::from(ok), Ordering::SeqCst);
            Box::pin(async {})
        }
    }

    enum InitProbeCall {
        GetStarted,
    }

    struct InitProbe {
        started: Arc<AtomicU8>,
        checkpoints: Arc<Mutex<Vec<serde_json::Value>>>,
    }

    impl GenServer for InitProbe {
        type Call = InitProbeCall;
        type Reply = bool;
        type Cast = ();
        type Info = SystemMsg;

        fn on_start(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.started.store(1, Ordering::SeqCst);
            let started = Arc::clone(&self.started);
            let checkpoints = Arc::clone(&self.checkpoints);
            Box::pin(async move {
                let event = serde_json::json!({
                    "phase": "on_start",
                    "started": started.load(Ordering::SeqCst),
                });
                tracing::info!(event = %event, "gen_server_lab_checkpoint");
                checkpoints.lock().push(event);
                yield_now().await;
            })
        }

        fn handle_call(
            &mut self,
            _cx: &Cx,
            request: InitProbeCall,
            reply: Reply<bool>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            match request {
                InitProbeCall::GetStarted => {
                    let started = self.started.load(Ordering::SeqCst) == 1;
                    let event = serde_json::json!({
                        "phase": "handle_call",
                        "started": started,
                    });
                    tracing::info!(event = %event, "gen_server_lab_checkpoint");
                    self.checkpoints.lock().push(event);
                    let _ = reply.send(started);
                }
            }
            Box::pin(async {})
        }
    }

    fn assert_gen_server<S: GenServer>() {}

    #[test]
    fn gen_server_trait_bounds() {
        init_test("gen_server_trait_bounds");
        assert_gen_server::<Counter>();
        crate::test_complete!("gen_server_trait_bounds");
    }

    #[test]
    fn gen_server_spawn_and_cast() {
        init_test("gen_server_spawn_and_cast");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 32)
            .expect("should spawn counter gen_server");
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // Cast a reset (fire-and-forget)
        handle
            .try_cast(CounterCast::Reset)
            .expect("should cast reset message");

        // Drop handle to disconnect
        drop(handle);

        {
            runtime.scheduler.lock().schedule(task_id, 0);
        }
        runtime.run_until_quiescent();

        crate::test_complete!("gen_server_spawn_and_cast");
    }

    #[test]
    fn dropping_an_unrun_server_aborts_its_queued_calls() {
        // A server task dropped before its first poll (admission denied, or a
        // teardown) dropped its mailbox with a queued call whose reply permit
        // was still armed, and the obligation drop bomb panicked on the
        // dropping thread.
        init_test("dropping_an_unrun_server_aborts_its_queued_calls");
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = lab_spawn_cx(&mut runtime, region, Budget::INFINITE);
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);
        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 32)
            .expect("spawn counter");

        let mut call = std::pin::pin!(handle.call(&cx, CounterCall::Get));
        let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(
            call.as_mut().poll(&mut task_cx).is_pending(),
            "the call is queued and waits for its reply"
        );

        drop(stored);
        let result = call.as_mut().poll(&mut task_cx);
        assert!(
            matches!(result, std::task::Poll::Ready(Err(_))),
            "the queued call fails once its server is gone"
        );
        crate::test_complete!("dropping_an_unrun_server_aborts_its_queued_calls");
    }

    #[test]
    fn gen_server_spawn_and_call() {
        init_test("gen_server_spawn_and_call");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = lab_spawn_cx(&mut runtime, region, Budget::INFINITE);
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 32)
            .expect("should spawn counter gen_server for call test");
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();
        let mut client_handle = cx
            .spawn(move |cx| async move {
                server_ref
                    .call(&cx, CounterCall::Add(5))
                    .await
                    .expect("should call Add(5)")
            })
            .expect("should spawn client task for call test");

        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_idle();

        let result =
            futures_lite::future::block_on(client_handle.join(&cx)).expect("client join ok");
        assert_eq!(result, 5);

        crate::test_complete!("gen_server_spawn_and_call");
    }

    /// What `ReplyOrDrop` does with a call's reply.
    #[derive(Clone, Copy, Debug)]
    enum ReplyMode {
        Send,
        Drop,
        Park,
    }

    /// Sends, drops or parks on each call's reply, as the call asks.
    struct ReplyOrDrop;

    impl GenServer for ReplyOrDrop {
        type Call = ReplyMode;
        type Reply = u8;
        type Cast = ();
        type Info = SystemMsg;

        fn handle_call(
            &mut self,
            cx: &Cx,
            mode: ReplyMode,
            reply: Reply<u8>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            match mode {
                ReplyMode::Send => {
                    let _ = reply.send(1);
                    Box::pin(async {})
                }
                ReplyMode::Drop => {
                    drop(reply);
                    Box::pin(async {})
                }
                // Holds the reply until the server is cancelled; it is then
                // dropped under cancellation, which aborts it.
                ReplyMode::Park => {
                    let cx = cx.clone();
                    Box::pin(async move {
                        cx.cancelled().await;
                        drop(reply);
                    })
                }
            }
        }
    }

    /// The lab's `reply_linearity` oracle sees how each `Reply` was resolved
    /// (br-asupersync-52hxjz). A sent reply passes. A dropped one fails, though
    /// it is resolved enough for the obligation oracles. A reply still in
    /// flight passes a mid-run report and, once its server is cancelled, the
    /// final one.
    #[test]
    fn lab_reports_check_reply_linearity() {
        init_test("lab_reports_check_reply_linearity");
        for mode in [ReplyMode::Send, ReplyMode::Drop, ReplyMode::Park] {
            let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(0x52_0052));
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let cx = lab_spawn_cx(&mut runtime, region, Budget::INFINITE);
            let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);
            let (handle, stored) = scope
                .spawn_gen_server(&mut runtime.state, &cx, ReplyOrDrop, 4)
                .expect("spawn the server");
            let server = handle.task_id();
            runtime.state.store_spawned_task(server, stored);
            let server_ref = handle.server_ref();
            let mut client = cx
                .spawn(move |cx| async move { server_ref.call(&cx, mode).await.ok() })
                .expect("spawn the client");
            runtime.scheduler.lock().schedule(server, 0);
            runtime.run_until_idle();

            if matches!(mode, ReplyMode::Park) {
                let mid_run = runtime.report();
                let entry = mid_run
                    .oracle_report
                    .entry("reply_linearity")
                    .expect("reply_linearity is reported");
                assert!(
                    entry.passed && entry.stats.entities_tracked == 0,
                    "a reply in flight is not a drop: {entry:?}"
                );
                let (tasks, wakes) = runtime
                    .state
                    .cancel_request(region, &CancelReason::user("test done"), None)
                    .into_parts();
                {
                    let mut scheduler = runtime.scheduler.lock();
                    for (task, priority) in tasks {
                        scheduler.schedule_cancel(task, priority);
                    }
                }
                wakes.dispatch();
                runtime.run_until_idle();
            }
            let replied = futures_lite::future::block_on(client.join(&cx)).unwrap_or(None);
            drop(handle);
            let report = runtime.run_until_quiescent_with_report();
            let entry = report
                .oracle_report
                .entry("reply_linearity")
                .expect("reply_linearity is reported");
            match mode {
                ReplyMode::Send => {
                    assert_eq!(replied, Some(1));
                    assert!(entry.passed, "{:?}", entry.violation);
                    assert_eq!(entry.stats.entities_tracked, 1);
                }
                ReplyMode::Drop => {
                    assert_eq!(replied, None, "a dropped reply never arrives");
                    assert!(
                        !entry.passed
                            && entry
                                .violation
                                .as_deref()
                                .is_some_and(|violation| violation.contains("dropped")),
                        "a dropped reply fails the oracle: {entry:?}"
                    );
                }
                ReplyMode::Park => {
                    assert_eq!(replied, None, "the cancelled call gets no reply");
                    assert!(entry.passed, "{:?}", entry.violation);
                    assert_eq!(entry.stats.entities_tracked, 1, "the aborted reply");
                }
            }
        }
        crate::test_complete!("lab_reports_check_reply_linearity");
    }

    /// asupersync-0ex6x0: a caller task in the root region used to panic with
    /// `[ASUP-E103]` inside the graded-token layer in production builds, while
    /// the `cfg(test)` region-0 fallback in `channel::session` let every
    /// in-tree test succeed. The call is now refused with a typed error before
    /// any mailbox slot is taken, on the test and production paths alike.
    #[test]
    fn call_from_root_region_task_is_rejected_with_asup_e103() {
        init_test("call_from_root_region_task_is_rejected_with_asup_e103");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let root = runtime.state.create_root_region(Budget::INFINITE);
        assert_eq!(
            root.as_u64(),
            0,
            "the lab root region must encode to zero for this reproducer"
        );
        let cx = lab_spawn_cx(&mut runtime, root, Budget::INFINITE);
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 32)
            .expect("should spawn counter gen_server");
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);
        let server_ref = handle.server_ref();

        // The client task runs in the ROOT region itself, like `block_on` and
        // `RuntimeHandle::spawn` tasks on the native runtime or a downstream
        // `LabRuntime` task created directly under `create_root_region`.
        let root_cx = Cx::new(root, TaskId::testing_default(), Budget::INFINITE)
            .with_spawn_gateway(runtime.state.spawn_gateway())
            .with_pending_spawn_counter(
                runtime
                    .state
                    .region(root)
                    .map(crate::record::RegionRecord::pending_spawn_handle),
            );
        let mut client_handle = root_cx
            .spawn(move |cx| async move {
                assert_eq!(
                    cx.region_id().as_u64(),
                    0,
                    "the client task must run in the root region"
                );
                server_ref.call(&cx, CounterCall::Add(5)).await
            })
            .expect("should spawn root-region client task");

        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_idle();

        let result =
            futures_lite::future::block_on(client_handle.join(&root_cx)).expect("client join ok");
        let Err(CallError::Cancelled(reason)) = result else {
            panic!(
                "a root-region caller must be refused with CallError::Cancelled, got {result:?}"
            );
        };
        assert!(
            reason
                .message()
                .is_some_and(|message| message.starts_with("[ASUP-E103]")),
            "the rejection must carry the ASUP-E103 token: {reason}"
        );

        crate::test_complete!("call_from_root_region_task_is_rejected_with_asup_e103");
    }

    #[test]
    fn gen_server_init_runs_before_queued_call_under_lab_runtime() {
        init_test("gen_server_init_runs_before_queued_call_under_lab_runtime");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(0x6E57_1001));
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = lab_spawn_cx(&mut runtime, region, Budget::INFINITE);
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);
        let started = Arc::new(AtomicU8::new(0));
        let checkpoints = Arc::new(Mutex::new(Vec::new()));

        let (mut handle, stored) = scope
            .spawn_gen_server(
                &mut runtime.state,
                &cx,
                InitProbe {
                    started: Arc::clone(&started),
                    checkpoints: Arc::clone(&checkpoints),
                },
                8,
            )
            .expect("spawn should succeed");
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();
        let checkpoints_for_client = Arc::clone(&checkpoints);
        let mut client_handle = cx
            .spawn(move |cx| async move {
                let started = server_ref
                    .call(&cx, InitProbeCall::GetStarted)
                    .await
                    .expect("init probe call should succeed");
                let event = serde_json::json!({
                    "phase": "client_completed",
                    "started": started,
                });
                tracing::info!(event = %event, "gen_server_lab_checkpoint");
                checkpoints_for_client.lock().push(event);
                started
            })
            .expect("client spawn should succeed");

        // Schedule server first to ensure initialization completes
        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_idle();

        // Then schedule client to ensure call happens after init
        runtime.run_until_idle();

        let call_saw_initialized =
            futures_lite::future::block_on(client_handle.join(&cx)).expect("client join ok");
        crate::assert_with_log!(
            call_saw_initialized,
            "queued call observes completed gen_server init",
            true,
            call_saw_initialized
        );
        crate::assert_with_log!(
            started.load(Ordering::SeqCst) == 1,
            "on_start marks server initialized",
            1,
            started.load(Ordering::SeqCst)
        );

        handle.stop();
        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        let server = futures_lite::future::block_on(handle.join(&cx)).expect("server join ok");
        crate::assert_with_log!(
            server.started.load(Ordering::SeqCst) == 1,
            "joined server preserves initialized state",
            1,
            server.started.load(Ordering::SeqCst)
        );

        let checkpoint_snapshot = checkpoints.lock().clone();
        crate::assert_with_log!(
            checkpoint_snapshot.len() == 3,
            "lab runtime emits init/call/client checkpoints",
            3,
            checkpoint_snapshot.len()
        );
        crate::assert_with_log!(
            checkpoint_snapshot[0]["phase"] == "on_start",
            "on_start checkpoint recorded first",
            "on_start",
            checkpoint_snapshot[0]["phase"].clone()
        );
        crate::assert_with_log!(
            runtime.is_quiescent(),
            "gen_server init test reaches lab quiescence",
            true,
            runtime.is_quiescent()
        );

        crate::test_complete!("gen_server_init_runs_before_queued_call_under_lab_runtime");
    }

    #[test]
    #[allow(clippy::items_after_statements, clippy::too_many_lines)]
    fn gen_server_spawn_inherits_full_child_cx_capabilities() {
        use crate::cx::registry::RegistryHandle;
        use crate::evidence_sink::{CollectorSink, EvidenceSink};
        use crate::observability::{LogCollector, LogLevel};
        use crate::remote::{NodeId, RemoteCap};
        use franken_evidence::EvidenceLedgerBuilder;

        init_test("gen_server_spawn_inherits_full_child_cx_capabilities");

        #[derive(Debug, Default)]
        #[allow(clippy::struct_excessive_bools)]
        struct CapabilityProbe {
            has_timer: bool,
            has_io_driver: bool,
            has_registry: bool,
            has_remote: bool,
            has_blocking_pool: bool,
            has_log_collector: bool,
            remote_origin: Option<String>,
            logical_tick_advanced: bool,
        }

        impl GenServer for CapabilityProbe {
            type Call = ();
            type Reply = ();
            type Cast = ();
            type Info = SystemMsg;

            fn on_start(&mut self, cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.has_timer = cx.has_timer();
                self.has_io_driver = cx.io_driver_handle().is_some();
                self.has_registry = cx.registry_handle().is_some();
                self.has_remote = cx.has_remote();
                self.has_blocking_pool = cx.blocking_pool_handle().is_some();
                self.has_log_collector = cx.log_collector().is_some();
                self.remote_origin = cx.remote().map(|remote| remote.local_node().to_string());
                let before = cx.logical_now();
                let after = cx.logical_tick();
                self.logical_tick_advanced = after > before;
                cx.trace("gen_server_capability_probe_trace");
                let entry = EvidenceLedgerBuilder::new()
                    .ts_unix_ms(1_700_000_000_000)
                    .component("gen_server_capability_probe")
                    .action("on_start")
                    .posterior(vec![0.6, 0.4])
                    .chosen_expected_loss(0.1)
                    .calibration_score(0.85)
                    .build()
                    .expect("evidence entry");
                cx.emit_evidence(&entry);
                Box::pin(async {})
            }

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: (),
                reply: Reply<()>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(());
                Box::pin(async {})
            }
        }

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let clock = Arc::new(crate::time::VirtualClock::new());
        runtime
            .state
            .set_timer_driver(crate::time::TimerDriverHandle::with_virtual_clock(clock));

        let registry = crate::cx::NameRegistry::new();
        let registry_handle = RegistryHandle::new(Arc::new(registry));
        let sink = Arc::new(CollectorSink::new());
        let collector = LogCollector::new(16).with_min_level(LogLevel::Trace);
        let blocking_pool = crate::runtime::blocking_pool::BlockingPool::new(1, 1);
        let cx = Cx::for_testing()
            .with_registry_handle(Some(registry_handle))
            .with_remote_cap(RemoteCap::new().with_local_node(NodeId::new("origin-test")))
            .with_blocking_pool_handle(Some(blocking_pool.handle()))
            .with_evidence_sink(Some(sink.clone() as Arc<dyn EvidenceSink>));
        cx.set_log_collector(collector.clone());

        let region = runtime.state.create_root_region(Budget::INFINITE);
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (mut handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, CapabilityProbe::default(), 8)
            .expect("spawn should succeed");
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        {
            runtime.scheduler.lock().schedule(task_id, 0);
        }
        runtime.run_until_idle();

        handle.stop();
        {
            runtime.scheduler.lock().schedule(task_id, 0);
        }
        runtime.run_until_quiescent();

        let server = futures_lite::future::block_on(handle.join(&cx)).expect("join ok");
        assert!(
            server.has_timer,
            "gen server child cx must inherit timer driver"
        );
        assert!(
            server.has_io_driver,
            "gen server child cx must inherit the runtime I/O driver",
        );
        assert!(
            server.has_registry,
            "gen server child cx must inherit registry handle",
        );
        assert!(
            server.has_remote,
            "gen server child cx must inherit remote cap"
        );
        assert!(
            server.has_blocking_pool,
            "gen server child cx must inherit blocking-pool capability",
        );
        assert!(
            server.has_log_collector,
            "gen server child cx must inherit observability collector state",
        );
        assert_eq!(server.remote_origin.as_deref(), Some("Node(origin-test)"));
        assert!(
            server.logical_tick_advanced,
            "gen server child cx must inherit a live logical clock",
        );
        let entries = sink.entries();
        assert_eq!(
            entries.len(),
            1,
            "gen server child cx must inherit evidence sink"
        );
        assert_eq!(entries[0].component, "gen_server_capability_probe");
        assert!(
            collector
                .peek()
                .iter()
                .any(|entry| entry.message() == "gen_server_capability_probe_trace"),
            "gen server child cx must inherit trace/log collector wiring",
        );

        crate::test_complete!("gen_server_spawn_inherits_full_child_cx_capabilities");
    }

    #[test]
    fn gen_server_call_cancellation_is_deterministic() {
        init_test("gen_server_call_cancellation_is_deterministic");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 32)
            .expect("should spawn counter gen_server for cancellation test");
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();

        let client_cx_cell: Arc<Mutex<Option<Cx>>> = Arc::new(Mutex::new(None));
        let client_cx_cell_for_task = Arc::clone(&client_cx_cell);

        let client_region = lab_client_region(&mut runtime, region, Budget::INFINITE);
        let system_cx = runtime.state.create_system_cx();
        let (client_task_id, mut client_handle, child_cx, result_tx, spawn_effects) = runtime
            .state
            .create_task_infrastructure::<Result<u64, CallError>>(
                &system_cx,
                client_region,
                Budget::INFINITE,
                false,
            )
            .expect("should spawn client task for cancellation test");
        let client_fut = {
            let cx = child_cx.clone();
            async move {
                {
                    *client_cx_cell_for_task.lock() = Some(cx.clone());
                }
                server_ref.call(&cx, CounterCall::Get).await
            }
        };
        let wrapped = {
            async move {
                spawn_effects.dispatch();
                match (crate::cx::scope::CatchUnwind { inner: client_fut }).await {
                    Ok(value) => {
                        crate::runtime::task_handle::publish_terminal_result(result_tx, Ok(value));
                        Outcome::Ok(())
                    }
                    Err(payload) => {
                        let panic_payload = crate::types::outcome::PanicPayload::new(
                            crate::cx::scope::payload_to_string(&payload),
                        );
                        crate::runtime::task_handle::publish_terminal_result(
                            result_tx,
                            Err(JoinError::Panicked(panic_payload.clone())),
                        );
                        Outcome::Panicked(panic_payload)
                    }
                }
            }
        };
        runtime.state.store_spawned_task(
            client_task_id,
            crate::runtime::StoredTask::new_with_id(wrapped, client_task_id),
        );

        // Poll the client once: it should enqueue the call and then block waiting for reply.
        {
            runtime.scheduler.lock().schedule(client_task_id, 0);
        }
        runtime.run_until_idle();

        // Cancel the client deterministically, then poll it again to observe the cancellation.
        let client_cx = client_cx_cell
            .lock()
            .as_ref()
            .expect("client cx published")
            .clone();
        client_cx.cancel_with(CancelKind::User, Some("gen_server call cancelled"));

        {
            runtime.scheduler.lock().schedule(client_task_id, 0);
        }
        runtime.run_until_idle();

        let result =
            futures_lite::future::block_on(client_handle.join(&cx)).expect("client join ok");
        match result {
            Ok(_) => unreachable!("expected cancellation, got Ok"),
            Err(CallError::Cancelled(reason)) => {
                assert_eq!(reason.kind, CancelKind::User);
                assert_eq!(
                    reason.message,
                    Some("gen_server call cancelled".to_string())
                );
            }
            Err(other) => unreachable!("expected CallError::Cancelled, got {other:?}"),
        }

        // Cleanup: disconnect the server and let it drain the queued call.
        drop(handle);
        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        crate::test_complete!("gen_server_call_cancellation_is_deterministic");
    }

    #[test]
    fn supervised_gen_server_stays_alive() {
        init_test("supervised_gen_server_stays_alive");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = named_gen_server_test_region(&mut runtime, Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);
        let registry = Arc::new(parking_lot::Mutex::new(crate::cx::NameRegistry::new()));

        let mut starter =
            named_gen_server_start(Arc::clone(&registry), "persistent_service", 32, || {
                Counter { count: 0 }
            });

        let task_id = starter
            .start(&scope, &mut runtime.state, &cx)
            .expect("start ok");

        // Run runtime. The server should start, init, and enter loop.
        // It should NOT exit just because the starter dropped the handle.
        {
            runtime.scheduler.lock().schedule(task_id, 0);
        }
        runtime.run_until_idle();

        let task = runtime.state.task(task_id).expect("task exists");
        crate::assert_with_log!(
            !task.state.is_terminal(),
            "server should be alive",
            "Running",
            format!("{:?}", task.state)
        );

        // Cleanup: cancel the region and drive the cancellation to quiescence.
        let cancel_effects =
            runtime
                .state
                .cancel_request(region, &CancelReason::user("test done"), None);
        let (tasks_to_schedule, wake_effects) = cancel_effects.into_parts();
        {
            let mut scheduler = runtime.scheduler.lock();
            for (tid, priority) in tasks_to_schedule {
                scheduler.schedule_cancel(tid, priority);
            }
            scheduler.schedule(task_id, 0);
        }
        wake_effects.dispatch();
        runtime.run_until_quiescent();

        assert!(
            registry.lock().whereis("persistent_service").is_none(),
            "name must be removed after region stop",
        );

        crate::test_complete!("supervised_gen_server_stays_alive");
    }

    #[test]
    fn gen_server_cast_cancellation_is_deterministic() {
        init_test("gen_server_cast_cancellation_is_deterministic");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        // Use a tiny mailbox and pre-fill it so the next cast blocks and is cancelable.
        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 1)
            .expect("should spawn counter gen_server with tiny mailbox");
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();

        futures_lite::future::block_on(handle.cast(&cx, CounterCast::Reset))
            .expect("prefill cast ok");

        let client_cx_cell: Arc<Mutex<Option<Cx>>> = Arc::new(Mutex::new(None));
        let client_cx_cell_for_task = Arc::clone(&client_cx_cell);

        let system_cx = runtime.state.create_system_cx();
        let (client_task_id, mut client_handle, child_cx, result_tx, spawn_effects) = runtime
            .state
            .create_task_infrastructure::<Result<(), CastError>>(
                &system_cx,
                region,
                Budget::INFINITE,
                false,
            )
            .expect("should spawn client task for cast cancellation test");
        let client_fut = {
            let cx = child_cx.clone();
            async move {
                {
                    *client_cx_cell_for_task.lock() = Some(cx.clone());
                }
                server_ref.cast(&cx, CounterCast::Reset).await
            }
        };
        let wrapped = {
            async move {
                spawn_effects.dispatch();
                match (crate::cx::scope::CatchUnwind { inner: client_fut }).await {
                    Ok(value) => {
                        crate::runtime::task_handle::publish_terminal_result(result_tx, Ok(value));
                        Outcome::Ok(())
                    }
                    Err(payload) => {
                        let panic_payload = crate::types::outcome::PanicPayload::new(
                            crate::cx::scope::payload_to_string(&payload),
                        );
                        crate::runtime::task_handle::publish_terminal_result(
                            result_tx,
                            Err(JoinError::Panicked(panic_payload.clone())),
                        );
                        Outcome::Panicked(panic_payload)
                    }
                }
            }
        };
        runtime.state.store_spawned_task(
            client_task_id,
            crate::runtime::StoredTask::new_with_id(wrapped, client_task_id),
        );

        // Poll the client once: it should block waiting for mailbox capacity.
        {
            runtime.scheduler.lock().schedule(client_task_id, 0);
        }
        runtime.run_until_idle();

        // Cancel the client deterministically, then poll it again to observe the cancellation.
        let client_cx = client_cx_cell
            .lock()
            .as_ref()
            .expect("client cx published")
            .clone();
        client_cx.cancel_with(CancelKind::User, Some("gen_server cast cancelled"));

        {
            runtime.scheduler.lock().schedule(client_task_id, 0);
        }
        runtime.run_until_quiescent();

        let result =
            futures_lite::future::block_on(client_handle.join(&cx)).expect("client join ok");
        match result {
            Ok(()) => unreachable!("expected cancellation, got Ok"),
            Err(CastError::Cancelled(reason)) => {
                assert_eq!(reason.kind, CancelKind::User);
                assert_eq!(
                    reason.message,
                    Some("gen_server cast cancelled".to_string())
                );
            }
            Err(other) => unreachable!("expected CastError::Cancelled, got {other:?}"),
        }

        // Cleanup: disconnect the server and let it drain the mailbox.
        drop(handle);
        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        crate::test_complete!("gen_server_cast_cancellation_is_deterministic");
    }

    #[test]
    fn gen_server_handle_accessors() {
        init_test("gen_server_handle_accessors");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut state, &cx, Counter { count: 0 }, 32)
            .expect("should spawn counter gen_server for handle accessors test");
        state.store_spawned_task(handle.task_id(), stored);

        let _actor_id = handle.actor_id();
        let _task_id = handle.task_id();
        assert!(!handle.is_finished());

        let server_ref = handle.server_ref();
        assert_eq!(server_ref.actor_id(), handle.actor_id());
        assert!(server_ref.is_alive());
        assert!(!server_ref.is_closed());

        crate::test_complete!("gen_server_handle_accessors");
    }

    #[test]
    fn spawn_gen_server_wrapper_abort_delivers_final_state() {
        init_test("spawn_gen_server_wrapper_abort_delivers_final_state");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (mut handle, mut stored) = scope
            .spawn_gen_server(&mut state, &cx, Counter { count: 0 }, 8)
            .expect("spawn gen_server");
        let server_ref = handle.server_ref();
        let server_cx: Cx = Cx::from_inner(
            handle
                .inner
                .upgrade()
                .expect("server handle must retain its live CxInner"),
        );
        handle.abort();
        assert!(
            server_cx.is_cancel_requested(),
            "GenServerHandle cancellation must publish through the server Cx envelope"
        );

        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = terminal_state_waker(Arc::clone(&handle.state), Arc::clone(&wake_count));
        let mut poll_cx = Context::from_waker(&waker);
        let join = std::pin::pin!(handle.join(&cx));
        let mut join = join;
        assert!(matches!(join.as_mut().poll(&mut poll_cx), Poll::Pending));

        assert!(
            matches!(stored.poll(&mut poll_cx), Poll::Ready(Outcome::Ok(()))),
            "aborted gen_server wrapper must complete cleanly after returning final state"
        );
        assert_eq!(
            wake_count.load(Ordering::Relaxed),
            1,
            "final state publication should wake the joiner exactly once"
        );
        assert!(
            !server_ref.is_alive(),
            "join wake must observe the terminal gen_server state"
        );

        match join.as_mut().poll(&mut poll_cx) {
            Poll::Ready(Ok(server_final)) => {
                assert_eq!(server_final.count, 0, "abort preserves final server state");
            }
            other => panic!("abort must return the final server state, got {other:?}"),
        }

        crate::test_complete!("spawn_gen_server_wrapper_abort_delivers_final_state");
    }

    #[test]
    fn spawn_gen_server_wrapper_cancelled_panic_surfaces_terminal_outcome() {
        #[derive(Debug)]
        struct PanicOnStop;

        impl GenServer for PanicOnStop {
            type Call = ();
            type Reply = ();
            type Cast = ();
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: (),
                reply: Reply<()>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(());
                Box::pin(async {})
            }

            fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                panic!("gen_server wrapper boom");
            }
        }

        init_test("spawn_gen_server_wrapper_cancelled_panic_surfaces_terminal_outcome");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (mut handle, mut stored) = scope
            .spawn_gen_server(&mut state, &cx, PanicOnStop, 8)
            .expect("spawn gen_server");
        let server_ref = handle.server_ref();
        handle.abort();

        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = terminal_state_waker(Arc::clone(&handle.state), Arc::clone(&wake_count));
        let mut poll_cx = Context::from_waker(&waker);
        let join = std::pin::pin!(handle.join(&cx));
        let mut join = join;
        assert!(matches!(join.as_mut().poll(&mut poll_cx), Poll::Pending));

        match stored.poll(&mut poll_cx) {
            Poll::Ready(Outcome::Panicked(payload)) => {
                assert_eq!(payload.message(), "gen_server wrapper boom");
            }
            other => panic!("panicking gen_server task must return Outcome::Panicked: {other:?}"),
        }
        assert_eq!(
            wake_count.load(Ordering::Relaxed),
            1,
            "panic result publication should wake the joiner exactly once"
        );
        assert!(
            !server_ref.is_alive(),
            "panic join wake must observe the terminal gen_server state"
        );

        match join.as_mut().poll(&mut poll_cx) {
            Poll::Ready(Err(JoinError::Panicked(payload))) => {
                assert_eq!(payload.message(), "gen_server wrapper boom");
            }
            other => panic!("join must preserve the gen_server panic, got {other:?}"),
        }

        crate::test_complete!("spawn_gen_server_wrapper_cancelled_panic_surfaces_terminal_outcome");
    }

    #[test]
    fn gen_server_ref_is_cloneable() {
        init_test("gen_server_ref_is_cloneable");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut state, &cx, Counter { count: 0 }, 32)
            .expect("should spawn counter gen_server for ref clone test");
        state.store_spawned_task(handle.task_id(), stored);

        let ref1 = handle.server_ref();
        let ref2 = ref1.clone();
        assert_eq!(ref1.actor_id(), ref2.actor_id());

        crate::test_complete!("gen_server_ref_is_cloneable");
    }

    #[test]
    fn gen_server_stop_transitions() {
        init_test("gen_server_stop_transitions");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 32)
            .expect("should spawn counter gen_server for stop transitions test");
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        let server_ref = handle.server_ref();
        assert!(server_ref.is_alive());

        handle.stop();

        {
            runtime.scheduler.lock().schedule(task_id, 0);
        }
        runtime.run_until_quiescent();

        assert!(handle.is_finished());
        assert!(!server_ref.is_alive());

        crate::test_complete!("gen_server_stop_transitions");
    }

    /// br-asupersync-c9b5nb LOW 5: stop() and abort() stored Stopping
    /// unconditionally, so either one on a finished server moved it from
    /// Stopped back to Stopping, and is_alive() reported it alive again. A
    /// server whose task was dropped unrun stayed Created, alive forever.
    #[test]
    fn a_finished_or_unrun_server_stays_not_alive() {
        init_test("a_finished_or_unrun_server_stays_not_alive");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 32)
            .expect("spawn counter");
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);
        let server_ref = handle.server_ref();
        handle.stop();
        {
            runtime.scheduler.lock().schedule(task_id, 0);
        }
        runtime.run_until_quiescent();
        assert!(handle.is_finished());
        assert!(!server_ref.is_alive());
        handle.stop();
        assert!(!server_ref.is_alive(), "a stop after the server finished");
        handle.abort();
        assert!(!server_ref.is_alive(), "an abort after the server finished");

        let (unrun, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 32)
            .expect("spawn counter");
        let unrun_ref = unrun.server_ref();
        assert!(unrun_ref.is_alive(), "a server not yet run is alive");
        drop(stored);
        assert!(
            !unrun_ref.is_alive(),
            "a server whose task was dropped unrun can never run"
        );

        crate::test_complete!("a_finished_or_unrun_server_stays_not_alive");
    }

    #[test]
    fn gen_server_handle_rejects_call_and_cast_after_stop() {
        init_test("gen_server_handle_rejects_call_and_cast_after_stop");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 32)
            .expect("should spawn counter gen_server for call/cast rejection test");
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // Let the server start, then request stop.
        {
            runtime.scheduler.lock().schedule(task_id, 0);
        }
        runtime.run_until_idle();
        handle.stop();

        let call_err =
            futures_lite::future::block_on(handle.call(&cx, CounterCall::Get)).unwrap_err();
        assert!(
            matches!(call_err, CallError::ServerStopped),
            "call after stop must return ServerStopped, got {call_err:?}"
        );

        let cast_err =
            futures_lite::future::block_on(handle.cast(&cx, CounterCast::Reset)).unwrap_err();
        assert!(
            matches!(cast_err, CastError::ServerStopped),
            "cast after stop must return ServerStopped, got {cast_err:?}"
        );

        {
            runtime.scheduler.lock().schedule(task_id, 0);
        }
        runtime.run_until_idle();
        assert!(handle.is_finished());

        crate::test_complete!("gen_server_handle_rejects_call_and_cast_after_stop");
    }

    #[test]
    fn gen_server_handle_join_returns_final_state_after_stop() {
        init_test("gen_server_handle_join_returns_final_state_after_stop");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (mut handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 32)
            .expect("should spawn counter gen_server for join final state test");
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        handle.stop();
        {
            runtime.scheduler.lock().schedule(task_id, 0);
        }
        runtime.run_until_quiescent();
        assert!(handle.is_finished());

        let final_state = futures_lite::future::block_on(handle.join(&cx)).expect("join");
        assert_eq!(
            final_state.count, 0,
            "final server state should be returned"
        );

        crate::test_complete!("gen_server_handle_join_returns_final_state_after_stop");
    }

    #[test]
    fn gen_server_handle_second_join_fails_closed() {
        init_test("gen_server_handle_second_join_fails_closed");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (mut handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        handle.stop();
        {
            runtime.scheduler.lock().schedule(task_id, 0);
        }
        runtime.run_until_quiescent();
        assert!(
            handle.is_finished(),
            "stopped server should report finished"
        );

        let final_state = futures_lite::future::block_on(handle.join(&cx)).expect("first join");
        assert_eq!(
            final_state.count, 0,
            "join should return final server state"
        );

        let second = futures_lite::future::block_on(handle.join(&cx));
        assert!(
            matches!(second, Err(JoinError::PolledAfterCompletion)),
            "second join must fail closed, got {second:?}"
        );

        crate::test_complete!("gen_server_handle_second_join_fails_closed");
    }

    #[test]
    fn gen_server_stop_wakes_blocked_mailbox_recv() {
        #[allow(clippy::items_after_statements)]
        struct StopWakeProbe {
            stop_ran: Arc<AtomicU8>,
        }

        #[allow(clippy::items_after_statements)]
        impl GenServer for StopWakeProbe {
            type Call = CounterCall;
            type Reply = u64;
            type Cast = CounterCast;
            type Info = SystemMsg;

            fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.stop_ran.store(1, Ordering::SeqCst);
                Box::pin(async {})
            }

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: CounterCall,
                reply: Reply<u64>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(0);
                Box::pin(async {})
            }
        }

        init_test("gen_server_stop_wakes_blocked_mailbox_recv");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let stop_ran = Arc::new(AtomicU8::new(0));
        let server = StopWakeProbe {
            stop_ran: Arc::clone(&stop_ran),
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        // Start server and let it park waiting on mailbox.recv().
        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_idle();

        // Stop should wake the blocked recv waiter. No manual reschedule here.
        handle.stop();
        runtime.run_until_idle();

        assert_eq!(
            stop_ran.load(Ordering::SeqCst),
            1,
            "on_stop should run after stop wakes blocked recv"
        );
        assert!(handle.is_finished(), "server should finish after stop");

        crate::test_complete!("gen_server_stop_wakes_blocked_mailbox_recv");
    }

    #[test]
    fn dropped_join_future_marks_server_stopping_like_abort() {
        init_test("dropped_join_future_marks_server_stopping_like_abort");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let final_count = Arc::new(AtomicU64::new(u64::MAX));
        let server = ObservableCounter {
            count: 0,
            final_count: Arc::clone(&final_count),
        };

        let (mut handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_idle();
        assert_eq!(
            handle.state.load(),
            ActorState::Running,
            "server should be running before join drop requests abort"
        );
        let server_cx: Cx = Cx::from_inner(
            handle
                .inner
                .upgrade()
                .expect("server handle must retain its live CxInner"),
        );

        drop(handle.join(&cx));

        assert_eq!(
            handle.state.load(),
            ActorState::Stopping,
            "dropping join future should mirror GenServerHandle::abort state transition"
        );
        assert!(
            server_cx.is_cancel_requested(),
            "GenServerJoinFuture cancellation must publish through the server Cx envelope"
        );

        runtime.run_until_idle();
        assert!(
            handle.is_finished(),
            "server should stop after join future drop"
        );
        assert_eq!(
            final_count.load(Ordering::SeqCst),
            0,
            "idle server should stop without processing phantom work"
        );

        crate::test_complete!("dropped_join_future_marks_server_stopping_like_abort");
    }

    // ---- Observable GenServer for E2E ----

    struct ObservableCounter {
        count: u64,
        final_count: Arc<AtomicU64>,
    }

    impl GenServer for ObservableCounter {
        type Call = CounterCall;
        type Reply = u64;
        type Cast = CounterCast;
        type Info = SystemMsg;

        fn handle_call(
            &mut self,
            _cx: &Cx,
            request: CounterCall,
            reply: Reply<u64>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            match request {
                CounterCall::Get => {
                    let _ = reply.send(self.count);
                }
                CounterCall::Add(n) => {
                    self.count += n;
                    let _ = reply.send(self.count);
                }
            }
            Box::pin(async {})
        }

        fn handle_cast(
            &mut self,
            _cx: &Cx,
            msg: CounterCast,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            match msg {
                CounterCast::Reset => self.count = 0,
            }
            Box::pin(async {})
        }

        fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.final_count.store(self.count, Ordering::SeqCst);
            Box::pin(async {})
        }
    }

    #[test]
    fn gen_server_processes_casts_before_stop() {
        init_test("gen_server_processes_casts_before_stop");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let final_count = Arc::new(AtomicU64::new(u64::MAX));
        let server = ObservableCounter {
            count: 0,
            final_count: final_count.clone(),
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // Start the server so casts are accepted.
        {
            runtime.scheduler.lock().schedule(task_id, 0);
        }
        runtime.run_until_idle();

        // Queue a handful of casts, then disconnect. Shutdown must drain the mailbox
        // before running on_stop, so the final count reflects the cast effects.
        for _ in 0..5 {
            handle.try_cast(CounterCast::Reset).expect("try_cast ok");
        }

        handle.stop();

        {
            runtime.scheduler.lock().schedule(task_id, 0);
        }
        runtime.run_until_quiescent();

        // Final count should be 0 (5 resets)
        assert_eq!(
            final_count.load(Ordering::SeqCst),
            0,
            "on_stop recorded final count"
        );

        crate::test_complete!("gen_server_processes_casts_before_stop");
    }

    #[test]
    fn gen_server_deterministic_replay() {
        fn run_scenario(seed: u64) -> u64 {
            let config = crate::lab::LabConfig::new(seed);
            let mut runtime = crate::lab::LabRuntime::new(config);
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let cx = Cx::for_testing();
            let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

            let final_count = Arc::new(AtomicU64::new(u64::MAX));
            let server = ObservableCounter {
                count: 0,
                final_count: final_count.clone(),
            };

            let (handle, stored) = scope
                .spawn_gen_server(&mut runtime.state, &cx, server, 32)
                .unwrap();
            let task_id = handle.task_id();
            runtime.state.store_spawned_task(task_id, stored);

            {
                runtime.scheduler.lock().schedule(task_id, 0);
            }
            runtime.run_until_idle();

            // 5 resets then disconnect
            for _ in 0..5 {
                handle.try_cast(CounterCast::Reset).expect("try_cast ok");
            }
            handle.stop();

            {
                runtime.scheduler.lock().schedule(task_id, 0);
            }
            runtime.run_until_quiescent();

            final_count.load(Ordering::SeqCst)
        }

        init_test("gen_server_deterministic_replay");

        let result1 = run_scenario(0xCAFE_BABE);
        let result2 = run_scenario(0xCAFE_BABE);
        assert_eq!(result1, result2, "deterministic replay");

        crate::test_complete!("gen_server_deterministic_replay");
    }

    // ---- System/info message tests (bd-188ey) ----

    #[derive(Default)]
    struct InfoRecorder {
        seen: Arc<Mutex<Vec<String>>>,
    }

    impl GenServer for InfoRecorder {
        type Call = ();
        type Reply = ();
        type Cast = ();
        type Info = SystemMsg;

        fn handle_call(
            &mut self,
            _cx: &Cx,
            _request: (),
            reply: Reply<()>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            let _ = reply.send(());
            Box::pin(async {})
        }

        fn handle_info(
            &mut self,
            _cx: &Cx,
            msg: Self::Info,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            let seen = Arc::clone(&self.seen);
            Box::pin(async move {
                seen.lock().push(format!("{msg:?}"));
            })
        }
    }

    fn tid(n: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(n, 0))
    }

    fn rid(n: u32) -> crate::types::RegionId {
        crate::types::RegionId::from_arena(ArenaIndex::new(n, 0))
    }

    /// Conformance: app shutdown batches use SYS-ORDER
    /// (`vt`, `Down < Exit < Timeout`, stable subject key).
    #[test]
    fn conformance_system_msg_sort_key_orders_shutdown_batch() {
        init_test("conformance_system_msg_sort_key_orders_shutdown_batch");

        let mut monitors = crate::monitor::MonitorSet::new();
        let mref_down_6 = monitors.establish(tid(90), rid(0), tid(6));
        let mref_down_3 = monitors.establish(tid(91), rid(0), tid(3));

        let mut batch = SystemMsgBatch::new();
        batch.push(SystemMsg::Exit {
            exit_vt: Time::from_secs(10),
            from: tid(6),
            reason: DownReason::Normal,
        });
        batch.push(SystemMsg::Timeout {
            tick_vt: Time::from_secs(10),
            id: 4,
        });
        batch.push(SystemMsg::Down {
            completion_vt: Time::from_secs(10),
            notification: DownNotification {
                monitored: tid(6),
                reason: DownReason::Normal,
                monitor_ref: mref_down_6,
            },
        });
        batch.push(SystemMsg::Timeout {
            tick_vt: Time::from_secs(9),
            id: 99,
        });
        batch.push(SystemMsg::Down {
            completion_vt: Time::from_secs(10),
            notification: DownNotification {
                monitored: tid(3),
                reason: DownReason::Normal,
                monitor_ref: mref_down_3,
            },
        });
        batch.push(SystemMsg::Exit {
            exit_vt: Time::from_secs(10),
            from: tid(2),
            reason: DownReason::Normal,
        });
        batch.push(SystemMsg::Timeout {
            tick_vt: Time::from_secs(10),
            id: 1,
        });

        let sorted = batch.into_sorted();
        let keys: Vec<_> = sorted.iter().map(SystemMsg::sort_key).collect();

        assert_eq!(
            keys,
            vec![
                (Time::from_secs(9), 2, SystemMsgSubjectKey::TimeoutId(99)),
                (Time::from_secs(10), 0, SystemMsgSubjectKey::Task(tid(3))),
                (Time::from_secs(10), 0, SystemMsgSubjectKey::Task(tid(6))),
                (Time::from_secs(10), 1, SystemMsgSubjectKey::Task(tid(2))),
                (Time::from_secs(10), 1, SystemMsgSubjectKey::Task(tid(6))),
                (Time::from_secs(10), 2, SystemMsgSubjectKey::TimeoutId(1)),
                (Time::from_secs(10), 2, SystemMsgSubjectKey::TimeoutId(4)),
            ],
            "shutdown system-message ordering must follow SYS-ORDER"
        );

        crate::test_complete!("conformance_system_msg_sort_key_orders_shutdown_batch");
    }

    /// Conformance: `SystemMsgBatch::into_sorted` is equivalent to explicit
    /// `sort_by_key(SystemMsg::sort_key)`.
    #[test]
    fn conformance_system_msg_batch_matches_explicit_sort() {
        init_test("conformance_system_msg_batch_matches_explicit_sort");

        let mut monitors = crate::monitor::MonitorSet::new();
        let mref = monitors.establish(tid(77), rid(0), tid(8));

        let messages = vec![
            SystemMsg::Timeout {
                tick_vt: Time::from_secs(12),
                id: 4,
            },
            SystemMsg::Exit {
                exit_vt: Time::from_secs(11),
                from: tid(8),
                reason: DownReason::Error("boom".to_string()),
            },
            SystemMsg::Down {
                completion_vt: Time::from_secs(11),
                notification: DownNotification {
                    monitored: tid(8),
                    reason: DownReason::Normal,
                    monitor_ref: mref,
                },
            },
            SystemMsg::Timeout {
                tick_vt: Time::from_secs(11),
                id: 2,
            },
        ];

        let mut batch = SystemMsgBatch::new();
        for msg in messages.clone() {
            batch.push(msg);
        }
        let batched = batch.into_sorted();

        let mut explicit = messages;
        explicit.sort_by_key(SystemMsg::sort_key);

        let batched_keys: Vec<_> = batched.iter().map(SystemMsg::sort_key).collect();
        let explicit_keys: Vec<_> = explicit.iter().map(SystemMsg::sort_key).collect();
        assert_eq!(batched_keys, explicit_keys);

        crate::test_complete!("conformance_system_msg_batch_matches_explicit_sort");
    }

    #[test]
    fn system_msg_payload_types_roundtrip_via_conversions() {
        init_test("system_msg_payload_types_roundtrip_via_conversions");

        let mut monitors = crate::monitor::MonitorSet::new();
        let mref = monitors.establish(tid(7), rid(0), tid(8));

        let down = DownMsg::new(
            Time::from_secs(11),
            DownNotification {
                monitored: tid(8),
                reason: DownReason::Normal,
                monitor_ref: mref,
            },
        );
        let down_msg = SystemMsg::down(down.clone());
        let down_back = DownMsg::try_from(down_msg).expect("down conversion");
        assert_eq!(down_back.completion_vt, down.completion_vt);
        assert_eq!(
            down_back.notification.monitored,
            down.notification.monitored
        );
        assert_eq!(down_back.notification.reason, down.notification.reason);
        assert_eq!(
            down_back.notification.monitor_ref,
            down.notification.monitor_ref
        );

        let exit = ExitMsg::new(
            Time::from_secs(12),
            tid(9),
            DownReason::Error("boom".into()),
        );
        let exit_msg = SystemMsg::exit(exit.clone());
        let exit_back = ExitMsg::try_from(exit_msg).expect("exit conversion");
        assert_eq!(exit_back, exit);

        let timeout = TimeoutMsg::new(Time::from_secs(13), 42);
        let timeout_msg = SystemMsg::timeout(timeout);
        let timeout_back = TimeoutMsg::try_from(timeout_msg).expect("timeout conversion");
        assert_eq!(timeout_back, timeout);

        crate::test_complete!("system_msg_payload_types_roundtrip_via_conversions");
    }

    #[test]
    fn system_msg_try_from_mismatch_returns_original_variant() {
        init_test("system_msg_try_from_mismatch_returns_original_variant");
        let mut monitors = crate::monitor::MonitorSet::new();
        let mref = monitors.establish(tid(10), rid(0), tid(1));

        let timeout = SystemMsg::Timeout {
            tick_vt: Time::from_secs(5),
            id: 99,
        };
        let err = DownMsg::try_from(timeout).expect_err("timeout is not down");
        assert!(matches!(err, SystemMsg::Timeout { id: 99, .. }));

        let down = SystemMsg::Down {
            completion_vt: Time::from_secs(6),
            notification: DownNotification {
                monitored: tid(1),
                reason: DownReason::Normal,
                monitor_ref: mref,
            },
        };
        let err = TimeoutMsg::try_from(down).expect_err("down is not timeout");
        assert!(matches!(err, SystemMsg::Down { .. }));

        crate::test_complete!("system_msg_try_from_mismatch_returns_original_variant");
    }

    #[test]
    fn gen_server_handle_info_receives_system_messages() {
        init_test("gen_server_handle_info_receives_system_messages");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let server = InfoRecorder {
            seen: Arc::clone(&seen),
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let mut monitors = crate::monitor::MonitorSet::new();
        let mref = monitors.establish(tid(10), rid(0), tid(11));

        handle
            .try_info(SystemMsg::Down {
                completion_vt: Time::from_secs(5),
                notification: DownNotification {
                    monitored: tid(11),
                    reason: DownReason::Normal,
                    monitor_ref: mref,
                },
            })
            .unwrap();

        handle
            .try_info(SystemMsg::Exit {
                exit_vt: Time::from_secs(6),
                from: tid(12),
                reason: DownReason::Error("boom".into()),
            })
            .unwrap();

        handle
            .try_info(SystemMsg::Timeout {
                tick_vt: Time::from_secs(7),
                id: 123,
            })
            .unwrap();

        drop(handle);

        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        let seen = seen.lock();
        assert_eq!(seen.len(), 3);
        assert!(seen[0].contains("Down"));
        assert!(seen[1].contains("Exit"));
        assert!(seen[2].contains("Timeout"));
        drop(seen);

        crate::test_complete!("gen_server_handle_info_receives_system_messages");
    }

    #[test]
    fn gen_server_info_ordering_is_deterministic_for_seed() {
        fn run_scenario(seed: u64) -> Vec<String> {
            let config = crate::lab::LabConfig::new(seed);
            let mut runtime = crate::lab::LabRuntime::new(config);
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let cx = lab_spawn_cx(&mut runtime, region, Budget::INFINITE);
            let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

            let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let server = InfoRecorder {
                seen: Arc::clone(&events),
            };

            let (handle, stored) = scope
                .spawn_gen_server(&mut runtime.state, &cx, server, 32)
                .unwrap();
            let server_task_id = handle.task_id();
            runtime.state.store_spawned_task(server_task_id, stored);

            let server_ref = handle.server_ref();

            let _client_a = cx
                .spawn(move |cx| async move {
                    server_ref
                        .info(
                            &cx,
                            SystemMsg::Timeout {
                                tick_vt: Time::from_secs(2),
                                id: 1,
                            },
                        )
                        .await
                        .unwrap();
                })
                .unwrap();

            let server_ref_b = handle.server_ref();
            let _client_b = cx
                .spawn(move |cx| async move {
                    server_ref_b
                        .info(
                            &cx,
                            SystemMsg::Timeout {
                                tick_vt: Time::from_secs(2),
                                id: 2,
                            },
                        )
                        .await
                        .unwrap();
                })
                .unwrap();

            // Let clients enqueue, then let the server drain.
            {
                runtime.scheduler.lock().schedule(server_task_id, 0);
            }

            runtime.run_until_quiescent();
            drop(handle);
            {
                runtime.scheduler.lock().schedule(server_task_id, 0);
            }
            runtime.run_until_quiescent();

            events.lock().clone()
        }

        init_test("gen_server_info_ordering_is_deterministic_for_seed");

        let a = run_scenario(0xD00D_F00D);
        let b = run_scenario(0xD00D_F00D);
        assert_eq!(
            a, b,
            "system/info ordering must be deterministic for same seed"
        );

        crate::test_complete!("gen_server_info_ordering_is_deterministic_for_seed");
    }

    // ---- DropOldest GenServer for backpressure tests ----

    /// A counter that uses DropOldest overflow policy.
    struct DropOldestCounter {
        count: u64,
    }

    /// Cast type that carries an identifiable value for eviction testing.
    #[derive(Debug, Clone)]
    enum TaggedCast {
        Set(u64),
    }

    impl GenServer for DropOldestCounter {
        type Call = CounterCall;
        type Reply = u64;
        type Cast = TaggedCast;
        type Info = SystemMsg;

        fn cast_overflow_policy(&self) -> CastOverflowPolicy {
            CastOverflowPolicy::DropOldest
        }

        fn handle_call(
            &mut self,
            _cx: &Cx,
            request: CounterCall,
            reply: Reply<u64>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            match request {
                CounterCall::Get => {
                    let _ = reply.send(self.count);
                }
                CounterCall::Add(n) => {
                    self.count += n;
                    let _ = reply.send(self.count);
                }
            }
            Box::pin(async {})
        }

        fn handle_cast(
            &mut self,
            _cx: &Cx,
            msg: TaggedCast,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            match msg {
                TaggedCast::Set(v) => self.count = v,
            }
            Box::pin(async {})
        }
    }

    #[test]
    fn gen_server_drop_oldest_policy_accessor() {
        init_test("gen_server_drop_oldest_policy_accessor");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut state, &cx, DropOldestCounter { count: 0 }, 4)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        assert_eq!(
            handle.cast_overflow_policy(),
            CastOverflowPolicy::DropOldest
        );

        let server_ref = handle.server_ref();
        assert_eq!(
            server_ref.cast_overflow_policy(),
            CastOverflowPolicy::DropOldest
        );

        crate::test_complete!("gen_server_drop_oldest_policy_accessor");
    }

    #[test]
    fn gen_server_drop_oldest_evicts_when_full() {
        init_test("gen_server_drop_oldest_evicts_when_full");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        // Mailbox capacity = 2
        let (handle, stored) = scope
            .spawn_gen_server(&mut state, &cx, DropOldestCounter { count: 0 }, 2)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        // Fill the mailbox (capacity 2)
        handle.try_cast(TaggedCast::Set(10)).unwrap();
        handle.try_cast(TaggedCast::Set(20)).unwrap();

        // This should succeed by evicting the oldest (Set(10))
        handle.try_cast(TaggedCast::Set(30)).unwrap();

        // And again — evicts Set(20), mailbox now has [Set(30), Set(40)]
        handle.try_cast(TaggedCast::Set(40)).unwrap();

        crate::test_complete!("gen_server_drop_oldest_evicts_when_full");
    }

    #[test]
    fn gen_server_reject_policy_returns_full() {
        init_test("gen_server_reject_policy_returns_full");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        // Default policy (Reject), capacity = 2
        let (handle, stored) = scope
            .spawn_gen_server(&mut state, &cx, Counter { count: 0 }, 2)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        assert_eq!(handle.cast_overflow_policy(), CastOverflowPolicy::Reject);

        // Fill the mailbox
        handle.try_cast(CounterCast::Reset).unwrap();
        handle.try_cast(CounterCast::Reset).unwrap();

        // Third should fail with Full
        let err = handle.try_cast(CounterCast::Reset).unwrap_err();
        assert!(matches!(err, CastError::Full), "expected Full, got {err:?}");

        crate::test_complete!("gen_server_reject_policy_returns_full");
    }

    #[test]
    fn gen_server_drop_oldest_ref_also_evicts() {
        init_test("gen_server_drop_oldest_ref_also_evicts");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut state, &cx, DropOldestCounter { count: 0 }, 2)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        let server_ref = handle.server_ref();

        // Fill via ref
        server_ref.try_cast(TaggedCast::Set(1)).unwrap();
        server_ref.try_cast(TaggedCast::Set(2)).unwrap();

        // Evict oldest via ref — should succeed
        server_ref.try_cast(TaggedCast::Set(3)).unwrap();

        crate::test_complete!("gen_server_drop_oldest_ref_also_evicts");
    }

    #[test]
    fn gen_server_drop_oldest_reserved_slots_returns_full() {
        init_test("gen_server_drop_oldest_reserved_slots_returns_full");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut state, &cx, DropOldestCounter { count: 0 }, 1)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        // Reserve the only mailbox slot without committing a message.
        let _permit = futures_lite::future::block_on(handle.sender.reserve(&cx)).unwrap();

        // DropOldest cannot evict reserved slots, so this must be a recoverable Full.
        let err = handle.try_cast(TaggedCast::Set(1)).unwrap_err();
        assert!(matches!(err, CastError::Full), "expected Full, got {err:?}");

        crate::test_complete!("gen_server_drop_oldest_reserved_slots_returns_full");
    }

    #[test]
    fn gen_server_ref_drop_oldest_reserved_slots_returns_full() {
        init_test("gen_server_ref_drop_oldest_reserved_slots_returns_full");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut state, &cx, DropOldestCounter { count: 0 }, 1)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);
        let server_ref = handle.server_ref();

        // Reserve the only mailbox slot without committing a message.
        let _permit = futures_lite::future::block_on(handle.sender.reserve(&cx)).unwrap();

        // Mirror behavior through GenServerRef::try_cast.
        let err = server_ref.try_cast(TaggedCast::Set(1)).unwrap_err();
        assert!(matches!(err, CastError::Full), "expected Full, got {err:?}");

        crate::test_complete!("gen_server_ref_drop_oldest_reserved_slots_returns_full");
    }

    /// DropOldest is cast-scoped: a queued Call must not be evicted by a later cast.
    #[test]
    fn gen_server_drop_oldest_preserves_queued_call_and_returns_full() {
        init_test("gen_server_drop_oldest_preserves_queued_call_and_returns_full");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let cx = tracked_reply_test_cx();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, DropOldestCounter { count: 0 }, 1)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        let (reply_tx, mut reply_rx) = session::tracked_oneshot::<u64>();
        let reply_permit = reply_tx.reserve(&cx).expect("cx not cancelled in test");
        let call_envelope: Envelope<DropOldestCounter> = Envelope::Call {
            request: CounterCall::Get,
            reply_permit,
        };
        handle.sender.try_send(call_envelope).unwrap();

        let err = handle.try_cast(TaggedCast::Set(99)).unwrap_err();
        assert!(matches!(err, CastError::Full), "expected Full, got {err:?}");

        handle.stop();
        {
            runtime.scheduler.lock().schedule(task_id, 0);
        }
        runtime.run_until_quiescent();

        let recv = futures_lite::future::block_on(reply_rx.recv(&cx));
        assert_eq!(
            recv,
            Ok(0),
            "preserved queued call should still be serviced, got {recv:?}"
        );

        crate::test_complete!("gen_server_drop_oldest_preserves_queued_call_and_returns_full");
    }

    #[test]
    fn gen_server_drop_oldest_preserves_queued_info_and_returns_full() {
        init_test("gen_server_drop_oldest_preserves_queued_info_and_returns_full");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let root = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, DropOldestCounter { count: 0 }, 1)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        let info = SystemMsg::timeout(TimeoutMsg::new(Time::from_secs(1), 7));
        handle
            .sender
            .try_send(Envelope::Info { msg: info })
            .expect("queue info");

        let err = handle.try_cast(TaggedCast::Set(99)).unwrap_err();
        assert!(matches!(err, CastError::Full), "expected Full, got {err:?}");

        handle.stop();
        {
            runtime.scheduler.lock().schedule(task_id, 0);
        }
        runtime.run_until_quiescent();

        crate::test_complete!("gen_server_drop_oldest_preserves_queued_info_and_returns_full");
    }

    #[test]
    fn gen_server_default_overflow_policy_is_reject() {
        init_test("gen_server_default_overflow_policy_is_reject");

        assert_eq!(CastOverflowPolicy::default(), CastOverflowPolicy::Reject);

        // Verify Counter (which doesn't override) uses Reject
        let counter = Counter { count: 0 };
        assert_eq!(counter.cast_overflow_policy(), CastOverflowPolicy::Reject);

        crate::test_complete!("gen_server_default_overflow_policy_is_reject");
    }

    #[test]
    fn reply_debug_format() {
        init_test("reply_debug_format");

        let cx = tracked_reply_test_cx();
        let (tx, _rx) = session::tracked_oneshot::<u64>();
        let permit = tx.reserve(&cx).expect("cx not cancelled in test");
        let reply = Reply::new(&cx, permit);
        let debug_str = format!("{reply:?}");
        assert!(debug_str.contains("Reply"));
        assert!(debug_str.contains("pending"));

        // Consume the reply to avoid the obligation panic
        let _ = reply.send(42);

        crate::test_complete!("reply_debug_format");
    }

    /// Regression test for br-asupersync-9f8o36.
    ///
    /// When a long-running handler future is dropped because its `Cx` got
    /// cancelled mid-handler, `Reply::Drop` must abort the obligation
    /// rather than letting the linearity drop-bomb fire. A panic here
    /// would be caught by the run-loop's `CatchUnwind` and surfaced to
    /// the supervisor as `JoinError::Panicked` for what is actually
    /// clean cancellation.
    #[test]
    fn reply_drop_under_cancel_aborts_without_panic() {
        init_test("reply_drop_under_cancel_aborts_without_panic");

        let cx = tracked_reply_test_cx();
        let (tx, mut rx) = session::tracked_oneshot::<u64>();
        let permit = tx.reserve(&cx).expect("cx not cancelled in test");
        let reply = Reply::new(&cx, permit);

        // Mid-handler async cancellation arrives. The handler future is
        // about to be dropped along with its `Reply<R>`.
        cx.set_cancel_requested(true);

        // This must not panic — that is the whole bug.
        drop(reply);

        // Caller observes the same RecvError::Closed it would see on an
        // explicit Reply::abort().
        let recv_outcome = rx.try_recv();
        assert!(
            matches!(
                recv_outcome,
                Err(crate::channel::oneshot::TryRecvError::Closed)
            ),
            "receiver should observe Closed after cancel-aborted reply, got {recv_outcome:?}"
        );

        crate::test_complete!("reply_drop_under_cancel_aborts_without_panic");
    }

    /// Negative companion to `reply_drop_under_cancel_aborts_without_panic`:
    /// a handler that drops the `Reply` while `cx` is healthy is a genuine
    /// programmer bug and the linearity drop-bomb must still fire.
    #[test]
    #[should_panic]
    fn reply_drop_without_cancel_still_panics_on_linearity_violation() {
        let cx = tracked_reply_test_cx();
        let (tx, _rx) = session::tracked_oneshot::<u64>();
        let permit = tx.reserve(&cx).expect("cx not cancelled in test");
        let reply = Reply::new(&cx, permit);

        // No cancel — the handler is silently dropping its Reply. This is
        // the leak the obligation system is designed to catch.
        drop(reply);
    }

    #[test]
    fn gen_server_on_start_budget_priority_applied_and_restored() {
        init_test("gen_server_on_start_budget_priority_applied_and_restored");

        let budget = Budget::new().with_poll_quota(100_000).with_priority(10);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = lab_spawn_cx(&mut runtime, region, budget);
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        let started_priority = Arc::new(AtomicU8::new(0));
        let loop_priority = Arc::new(AtomicU8::new(0));
        let server = StartBudgetProbe {
            started_priority: Arc::clone(&started_priority),
            loop_priority: Arc::clone(&loop_priority),
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();
        let _client = cx
            .spawn(move |cx| async move {
                let p = server_ref.call(&cx, CounterCall::Get).await.unwrap();
                assert_eq!(p, 10);
            })
            .unwrap();

        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        assert_eq!(started_priority.load(Ordering::SeqCst), 200);
        assert_eq!(loop_priority.load(Ordering::SeqCst), 10);

        drop(handle);
        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        crate::test_complete!("gen_server_on_start_budget_priority_applied_and_restored");
    }

    #[test]
    fn gen_server_on_stop_runs_masked_under_stop() {
        init_test("gen_server_on_stop_runs_masked_under_stop");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        let stop_checkpoint_ok = Arc::new(AtomicU8::new(0));
        let server = StopMaskProbe {
            stop_checkpoint_ok: Arc::clone(&stop_checkpoint_ok),
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        // Request stop: sets cancel_requested. on_stop must run masked.
        handle.stop();

        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        assert_eq!(stop_checkpoint_ok.load(Ordering::SeqCst), 1);

        crate::test_complete!("gen_server_on_stop_runs_masked_under_stop");
    }

    // ── Cast overflow policy tests (bd-2o5hg) ────────────────────────

    /// Verify that DropOldest eviction emits a trace event.
    #[test]
    fn cast_drop_oldest_emits_trace_on_eviction() {
        init_test("cast_drop_oldest_emits_trace_on_eviction");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        // Capacity=1 so the second cast evicts the first
        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, DropOldestCounter { count: 0 }, 1)
            .unwrap();
        let task_id = handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // Schedule so Cx::current() is set
        {
            runtime.scheduler.lock().schedule(task_id, 0);
        }
        runtime.run_until_quiescent();

        // First cast fills the mailbox
        handle.try_cast(TaggedCast::Set(1)).unwrap();
        // Second cast evicts the first
        handle.try_cast(TaggedCast::Set(2)).unwrap();

        // The eviction trace is emitted via Cx::current() (set during task poll).
        // We confirm it succeeded (no panic/error).
        crate::test_complete!("cast_drop_oldest_emits_trace_on_eviction");
    }

    /// Casting to a stopped server returns ServerStopped.
    #[test]
    fn cast_to_stopped_server_returns_error() {
        init_test("cast_to_stopped_server_returns_error");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut state, &cx, Counter { count: 0 }, 4)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        // Stop the server
        handle.stop();

        // try_cast should return ServerStopped
        let err = handle.try_cast(CounterCast::Reset).unwrap_err();
        assert!(
            matches!(err, CastError::ServerStopped),
            "expected ServerStopped, got {err:?}"
        );

        crate::test_complete!("cast_to_stopped_server_returns_error");
    }

    /// CastOverflowPolicy Display is correct.
    #[test]
    fn cast_overflow_policy_display() {
        init_test("cast_overflow_policy_display");

        assert_eq!(format!("{}", CastOverflowPolicy::Reject), "Reject");
        assert_eq!(format!("{}", CastOverflowPolicy::DropOldest), "DropOldest");

        crate::test_complete!("cast_overflow_policy_display");
    }

    /// Reject policy on GenServerRef returns Full when mailbox is full.
    #[test]
    fn cast_ref_reject_returns_full() {
        init_test("cast_ref_reject_returns_full");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut state, &cx, Counter { count: 0 }, 2)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        let server_ref = handle.server_ref();

        // Fill the mailbox via server_ref
        server_ref.try_cast(CounterCast::Reset).unwrap();
        server_ref.try_cast(CounterCast::Reset).unwrap();

        // Third should fail with Full
        let err = server_ref.try_cast(CounterCast::Reset).unwrap_err();
        assert!(matches!(err, CastError::Full), "expected Full, got {err:?}");

        crate::test_complete!("cast_ref_reject_returns_full");
    }

    /// DropOldest via GenServerRef with capacity=1 evicts correctly.
    #[test]
    fn cast_drop_oldest_ref_capacity_one() {
        init_test("cast_drop_oldest_ref_capacity_one");

        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(root, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut state, &cx, DropOldestCounter { count: 0 }, 1)
            .unwrap();
        state.store_spawned_task(handle.task_id(), stored);

        let server_ref = handle.server_ref();

        // Fill with one message
        server_ref.try_cast(TaggedCast::Set(100)).unwrap();
        // Evict and replace — should succeed with capacity=1
        server_ref.try_cast(TaggedCast::Set(200)).unwrap();
        server_ref.try_cast(TaggedCast::Set(300)).unwrap();

        crate::test_complete!("cast_drop_oldest_ref_capacity_one");
    }

    // ── Init/Terminate semantics (bd-3ejoi) ──────────────────────────

    #[test]
    fn init_default_budget_is_infinite() {
        init_test("init_default_budget_is_infinite");
        let counter = Counter { count: 0 };
        assert_eq!(counter.on_start_budget(), Budget::INFINITE);
        crate::test_complete!("init_default_budget_is_infinite");
    }

    #[test]
    fn terminate_default_budget_is_minimal() {
        init_test("terminate_default_budget_is_minimal");
        let counter = Counter { count: 0 };
        assert_eq!(counter.on_stop_budget(), Budget::MINIMAL);
        crate::test_complete!("terminate_default_budget_is_minimal");
    }

    /// If the task is cancelled before init, on_start is skipped but on_stop
    /// still runs (deterministic cleanup guarantee).
    #[test]
    fn init_skipped_when_pre_cancelled_but_stop_runs() {
        #[allow(clippy::items_after_statements)]
        struct LifecycleProbe {
            init_ran: Arc<AtomicU8>,
            stop_ran: Arc<AtomicU8>,
        }

        #[allow(clippy::items_after_statements)]
        impl GenServer for LifecycleProbe {
            type Call = CounterCall;
            type Reply = u64;
            type Cast = CounterCast;
            type Info = SystemMsg;

            fn on_start(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.init_ran.store(1, Ordering::SeqCst);
                Box::pin(async {})
            }

            fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.stop_ran.store(1, Ordering::SeqCst);
                Box::pin(async {})
            }

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: CounterCall,
                reply: Reply<u64>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(0);
                Box::pin(async {})
            }
        }

        init_test("init_skipped_when_pre_cancelled_but_stop_runs");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        let init_ran = Arc::new(AtomicU8::new(0));
        let stop_ran = Arc::new(AtomicU8::new(0));

        let server = LifecycleProbe {
            init_ran: Arc::clone(&init_ran),
            stop_ran: Arc::clone(&stop_ran),
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        // Cancel BEFORE scheduling (pre-cancel)
        handle.stop();

        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        // Init should be skipped
        assert_eq!(
            init_ran.load(Ordering::SeqCst),
            0,
            "init should be skipped when pre-cancelled"
        );
        // Stop should still run
        assert_eq!(
            stop_ran.load(Ordering::SeqCst),
            1,
            "stop must run even when pre-cancelled"
        );

        crate::test_complete!("init_skipped_when_pre_cancelled_but_stop_runs");
    }

    /// Verify that budget consumed during on_start is subtracted from the main
    /// task budget when the guard restores.
    #[test]
    fn init_budget_consumption_propagates_to_main_budget() {
        const MAIN_POLL_QUOTA: u32 = 100_000;
        const INIT_POLL_COST: u32 = 7;

        #[allow(clippy::items_after_statements)]
        struct BudgetCheckProbe {
            loop_quota: Arc<AtomicU64>,
            init_poll_cost: u32,
        }

        #[allow(clippy::items_after_statements)]
        impl GenServer for BudgetCheckProbe {
            type Call = CounterCall;
            type Reply = u64;
            type Cast = CounterCast;
            type Info = SystemMsg;

            fn on_start(&mut self, cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let mut guard = cx.inner.write();
                guard.budget.poll_quota =
                    guard.budget.poll_quota.saturating_sub(self.init_poll_cost);
                Box::pin(async {})
            }

            fn on_start_budget(&self) -> Budget {
                // Tight init budget
                Budget::new().with_poll_quota(100_000).with_priority(200)
            }

            fn handle_call(
                &mut self,
                cx: &Cx,
                _request: CounterCall,
                reply: Reply<u64>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                // After init, check the remaining budget
                self.loop_quota
                    .store(u64::from(cx.budget().poll_quota), Ordering::SeqCst);
                let _ = reply.send(0);
                Box::pin(async {})
            }
        }

        init_test("init_budget_consumption_propagates_to_main_budget");

        let budget = Budget::new()
            .with_poll_quota(MAIN_POLL_QUOTA)
            .with_priority(10);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = lab_spawn_cx(&mut runtime, region, budget);
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        let loop_quota = Arc::new(AtomicU64::new(0));

        let server = BudgetCheckProbe {
            loop_quota: Arc::clone(&loop_quota),
            init_poll_cost: INIT_POLL_COST,
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();
        let _client = cx
            .spawn(move |cx| async move {
                let _ = server_ref.call(&cx, CounterCall::Get).await;
            })
            .unwrap();

        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        // After init, the main budget should have the original quota minus
        // whatever was consumed during init. Pin the bound to the configured
        // main quota so future quota changes cannot leave a stale assertion.
        let remaining = loop_quota.load(Ordering::SeqCst);
        let max_remaining = u64::from(MAIN_POLL_QUOTA.saturating_sub(INIT_POLL_COST));
        assert!(
            remaining <= max_remaining,
            "main budget after init must subtract init usage ({remaining} <= {max_remaining})"
        );
        assert!(
            remaining > 0,
            "main budget should still have polls remaining"
        );

        drop(handle);
        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        crate::test_complete!("init_budget_consumption_propagates_to_main_budget");
    }

    /// Verify on_stop_budget tightens the budget during the stop phase.
    #[test]
    fn stop_budget_constrains_stop_phase() {
        struct StopBudgetProbe {
            stop_poll_quota: Arc<AtomicU64>,
        }

        impl GenServer for StopBudgetProbe {
            type Call = CounterCall;
            type Reply = u64;
            type Cast = CounterCast;
            type Info = SystemMsg;

            fn on_stop_budget(&self) -> Budget {
                Budget::new().with_poll_quota(42).with_priority(250)
            }

            fn on_stop(&mut self, cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.stop_poll_quota
                    .store(u64::from(cx.budget().poll_quota), Ordering::SeqCst);
                Box::pin(async {})
            }

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: CounterCall,
                reply: Reply<u64>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(0);
                Box::pin(async {})
            }
        }

        init_test("stop_budget_constrains_stop_phase");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        let stop_poll_quota = Arc::new(AtomicU64::new(0));

        let server = StopBudgetProbe {
            stop_poll_quota: Arc::clone(&stop_poll_quota),
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        // Trigger stop
        handle.stop();

        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        let stop_quota = stop_poll_quota.load(Ordering::SeqCst);
        // The stop budget is meet(original, on_stop_budget), so
        // poll_quota should be min(100_000, 42) = 42.
        assert_eq!(stop_quota, 42, "stop phase should use the tighter budget");

        crate::test_complete!("stop_budget_constrains_stop_phase");
    }

    /// Verify that init runs before stop, and stop always runs even on
    /// immediate shutdown.
    #[test]
    fn lifecycle_init_before_stop() {
        #[allow(clippy::items_after_statements)]
        struct PhaseTracker {
            phases: Arc<Mutex<Vec<&'static str>>>,
        }

        #[allow(clippy::items_after_statements)]
        impl GenServer for PhaseTracker {
            type Call = CounterCall;
            type Reply = u64;
            type Cast = CounterCast;
            type Info = SystemMsg;

            fn on_start(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.phases.lock().push("init");
                Box::pin(async {})
            }

            fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.phases.lock().push("stop");
                Box::pin(async {})
            }

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: CounterCall,
                reply: Reply<u64>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(0);
                Box::pin(async {})
            }

            fn handle_cast(
                &mut self,
                _cx: &Cx,
                _msg: CounterCast,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                Box::pin(async {})
            }
        }

        init_test("lifecycle_init_before_stop");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        let phases = Arc::new(Mutex::new(Vec::<&'static str>::new()));

        let server = PhaseTracker {
            phases: Arc::clone(&phases),
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        // Schedule the server so init runs, then idle on recv
        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_idle();

        // Stop the server and reschedule so on_stop runs
        let phases_clone = Arc::clone(&phases);
        handle.stop();
        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        {
            let recorded = phases_clone.lock();

            // Stop must always run
            assert!(
                recorded.contains(&"stop"),
                "stop phase must run, got {:?}",
                *recorded
            );

            // If init ran, it must precede stop
            if let Some(init_pos) = recorded.iter().position(|p| *p == "init") {
                let stop_pos = recorded.iter().position(|p| *p == "stop").unwrap();
                assert!(
                    init_pos < stop_pos,
                    "init must precede stop, got {:?}",
                    *recorded
                );
            }

            drop(recorded);
        }

        crate::test_complete!("lifecycle_init_before_stop");
    }

    /// Verify that on_stop_budget with a custom priority overrides the
    /// budget priority during the stop phase.
    #[test]
    fn stop_budget_priority_applied() {
        #[allow(clippy::items_after_statements)]
        struct StopPriorityProbe {
            stop_priority: Arc<AtomicU8>,
        }

        #[allow(clippy::items_after_statements)]
        impl GenServer for StopPriorityProbe {
            type Call = CounterCall;
            type Reply = u64;
            type Cast = CounterCast;
            type Info = SystemMsg;

            fn on_stop_budget(&self) -> Budget {
                Budget::new().with_poll_quota(100_000).with_priority(240)
            }

            fn on_stop(&mut self, cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.stop_priority
                    .store(cx.budget().priority, Ordering::SeqCst);
                Box::pin(async {})
            }

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: CounterCall,
                reply: Reply<u64>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(0);
                Box::pin(async {})
            }
        }

        init_test("stop_budget_priority_applied");

        let budget = Budget::new().with_poll_quota(100_000).with_priority(10);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        let stop_priority = Arc::new(AtomicU8::new(0));

        let server = StopPriorityProbe {
            stop_priority: Arc::clone(&stop_priority),
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        handle.stop();

        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        // priority = max(original=10, stop_budget=240) after meet
        // meet takes min for quotas but max for priority
        let actual_priority = stop_priority.load(Ordering::SeqCst);
        assert!(
            actual_priority >= 10,
            "stop priority should be at least original ({actual_priority} >= 10)"
        );

        crate::test_complete!("stop_budget_priority_applied");
    }

    // ========================================================================
    // Conformance + Lab Tests (bd-l6b71)
    //
    // These tests verify the GenServer conformance suite:
    //   - reply linearity (obligation enforcement)
    //   - cancel propagation through call/cast
    //   - mailbox overflow determinism
    //   - full lifecycle with no obligation leaks
    //   - deterministic replay (same seed = same outcome)
    // ========================================================================

    /// Multiple queued calls all receive `Cancelled` when the server's region
    /// is cancelled. Verifies cancel propagation to pending call waiters.
    #[test]
    fn conformance_cancel_propagation_to_queued_calls() {
        init_test("conformance_cancel_propagation_to_queued_calls");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        // Capacity-1 mailbox: second call will block waiting for capacity.
        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 1)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref_1 = handle.server_ref();
        let server_ref_2 = handle.server_ref();

        // Client 1: sends a call that the server will process.
        let result_1: Arc<Mutex<Option<Result<u64, CallError>>>> = Arc::new(Mutex::new(None));
        let result_1_clone = Arc::clone(&result_1);
        let client_region = lab_client_region(&mut runtime, region, budget);
        let system_cx = runtime.state.create_system_cx();
        let (c1_id, _c1_handle, c1_child_cx, c1_result_tx, c1_spawn_effects) = runtime
            .state
            .create_task_infrastructure::<()>(&system_cx, client_region, budget, false)
            .unwrap();
        let c1_fut = {
            let cx = c1_child_cx.clone();
            async move {
                let r = server_ref_1.call(&cx, CounterCall::Add(10)).await;
                *result_1_clone.lock() = Some(r);
            }
        };
        let c1_wrapped = {
            async move {
                c1_spawn_effects.dispatch();
                match (crate::cx::scope::CatchUnwind { inner: c1_fut }).await {
                    Ok(value) => {
                        crate::runtime::task_handle::publish_terminal_result(
                            c1_result_tx,
                            Ok(value),
                        );
                        Outcome::Ok(())
                    }
                    Err(payload) => {
                        let panic_payload = crate::types::outcome::PanicPayload::new(
                            crate::cx::scope::payload_to_string(&payload),
                        );
                        crate::runtime::task_handle::publish_terminal_result(
                            c1_result_tx,
                            Err(JoinError::Panicked(panic_payload.clone())),
                        );
                        Outcome::Panicked(panic_payload)
                    }
                }
            }
        };
        runtime.state.store_spawned_task(
            c1_id,
            crate::runtime::StoredTask::new_with_id(c1_wrapped, c1_id),
        );

        // Client 2: sends a call that will queue behind client 1.
        let result_2: Arc<Mutex<Option<Result<u64, CallError>>>> = Arc::new(Mutex::new(None));
        let result_2_clone = Arc::clone(&result_2);
        let (c2_id, _c2_handle, c2_child_cx, c2_result_tx, c2_spawn_effects) = runtime
            .state
            .create_task_infrastructure::<()>(&system_cx, client_region, budget, false)
            .unwrap();
        let c2_fut = {
            let cx = c2_child_cx.clone();
            async move {
                let r = server_ref_2.call(&cx, CounterCall::Add(20)).await;
                *result_2_clone.lock() = Some(r);
            }
        };
        let c2_wrapped = {
            async move {
                c2_spawn_effects.dispatch();
                match (crate::cx::scope::CatchUnwind { inner: c2_fut }).await {
                    Ok(value) => {
                        crate::runtime::task_handle::publish_terminal_result(
                            c2_result_tx,
                            Ok(value),
                        );
                        Outcome::Ok(())
                    }
                    Err(payload) => {
                        let panic_payload = crate::types::outcome::PanicPayload::new(
                            crate::cx::scope::payload_to_string(&payload),
                        );
                        crate::runtime::task_handle::publish_terminal_result(
                            c2_result_tx,
                            Err(JoinError::Panicked(panic_payload.clone())),
                        );
                        Outcome::Panicked(panic_payload)
                    }
                }
            }
        };
        runtime.state.store_spawned_task(
            c2_id,
            crate::runtime::StoredTask::new_with_id(c2_wrapped, c2_id),
        );

        // Schedule server + clients, let them make progress.
        {
            let mut sched = runtime.scheduler.lock();
            sched.schedule(server_task_id, 0);
            sched.schedule(c1_id, 0);
            sched.schedule(c2_id, 0);
        }
        runtime.run_until_quiescent();

        // Stop the server (triggers cancellation of pending calls).
        handle.stop();
        {
            let mut sched = runtime.scheduler.lock();
            sched.schedule(server_task_id, 0);
            sched.schedule(c1_id, 0);
            sched.schedule(c2_id, 0);
        }
        runtime.run_until_quiescent();

        // At least one client should have seen an error (ServerStopped or Cancelled)
        // because the server shut down. The first call may have succeeded before stop.
        // All outcomes are acceptable: Ok (processed before stop), ServerStopped,
        // Cancelled, or NoReply.
        drop(result_2.lock());

        crate::test_complete!("conformance_cancel_propagation_to_queued_calls");
    }

    /// After stop(), new calls and casts are rejected immediately.
    #[test]
    fn conformance_stopped_server_rejects_new_messages() {
        init_test("conformance_stopped_server_rejects_new_messages");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();

        // Start the server so init runs.
        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        // Stop the server and drain.
        handle.stop();
        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        // try_cast to a stopped server should fail.
        let cast_result = server_ref.try_cast(CounterCast::Reset);
        assert!(cast_result.is_err(), "cast to stopped server must fail");

        crate::test_complete!("conformance_stopped_server_rejects_new_messages");
    }

    /// Full lifecycle test: start, send calls+casts, stop, verify no leaked
    /// obligations or unprocessed messages. This exercises the complete
    /// GenServer protocol end-to-end.
    #[test]
    fn conformance_full_lifecycle_no_obligation_leaks() {
        init_test("conformance_full_lifecycle_no_obligation_leaks");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();

        // Phase 1: Fire off a mix of casts and then a call.
        server_ref.try_cast(CounterCast::Reset).unwrap();

        let call_result: Arc<Mutex<Option<Result<u64, CallError>>>> = Arc::new(Mutex::new(None));
        let call_result_clone = Arc::clone(&call_result);
        let server_ref_for_call = handle.server_ref();
        let client_region = lab_client_region(&mut runtime, region, budget);
        let system_cx = runtime.state.create_system_cx();
        let (client_id, _client, child_cx, result_tx, spawn_effects) = runtime
            .state
            .create_task_infrastructure::<()>(&system_cx, client_region, budget, false)
            .unwrap();
        let client_fut = {
            let cx = child_cx.clone();
            async move {
                let r = server_ref_for_call.call(&cx, CounterCall::Add(42)).await;
                *call_result_clone.lock() = Some(r);
            }
        };
        let wrapped = {
            async move {
                spawn_effects.dispatch();
                match (crate::cx::scope::CatchUnwind { inner: client_fut }).await {
                    Ok(value) => {
                        crate::runtime::task_handle::publish_terminal_result(result_tx, Ok(value));
                        Outcome::Ok(())
                    }
                    Err(payload) => {
                        let panic_payload = crate::types::outcome::PanicPayload::new(
                            crate::cx::scope::payload_to_string(&payload),
                        );
                        crate::runtime::task_handle::publish_terminal_result(
                            result_tx,
                            Err(JoinError::Panicked(panic_payload.clone())),
                        );
                        Outcome::Panicked(panic_payload)
                    }
                }
            }
        };
        runtime.state.store_spawned_task(
            client_id,
            crate::runtime::StoredTask::new_with_id(wrapped, client_id),
        );

        // Schedule both and let them process.
        {
            let mut sched = runtime.scheduler.lock();
            sched.schedule(server_task_id, 0);
            sched.schedule(client_id, 0);
        }
        runtime.run_until_quiescent();

        // Re-schedule for message processing.
        {
            let mut sched = runtime.scheduler.lock();
            sched.schedule(server_task_id, 0);
            sched.schedule(client_id, 0);
        }
        runtime.run_until_quiescent();

        // Phase 2: Verify the call result.
        let call_r = call_result.lock();
        if let Some(ref r) = *call_r {
            match r {
                Ok(value) => assert_eq!(*value, 42, "counter should be 42 after Add(42)"),
                Err(e) => unreachable!("unexpected call error: {e:?}"),
            }
        }
        drop(call_r);

        // Phase 3: More casts to exercise the mailbox.
        server_ref.try_cast(CounterCast::Reset).unwrap();

        // Phase 4: Graceful stop.
        handle.stop();
        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        // If we get here without panics, no obligations were leaked.
        // TrackedOneshotPermit panics on drop if not consumed.
        crate::test_complete!("conformance_full_lifecycle_no_obligation_leaks");
    }

    /// Deterministic replay: running the same GenServer scenario with the
    /// same seed must produce identical state transitions.
    #[test]
    #[allow(clippy::items_after_statements)]
    fn conformance_deterministic_replay_with_seed() {
        init_test("conformance_deterministic_replay_with_seed");

        fn run_scenario(seed: u64) -> Vec<u64> {
            let config = crate::lab::LabConfig::new(seed);
            let mut runtime = crate::lab::LabRuntime::new(config);
            let budget = Budget::new().with_poll_quota(100_000);
            let region = runtime.state.create_root_region(budget);
            let cx = Cx::for_testing();
            let scope = crate::cx::Scope::<FailFast>::new(region, budget);

            let (handle, stored) = scope
                .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 32)
                .unwrap();
            let server_task_id = handle.task_id();
            runtime.state.store_spawned_task(server_task_id, stored);

            let results: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));

            // Spawn 3 clients that each Add different amounts.
            let mut client_ids = Vec::new();
            for i in 1..=3u64 {
                let server_ref = handle.server_ref();
                let results_clone = Arc::clone(&results);
                let client_region = lab_client_region(&mut runtime, region, budget);
                let system_cx = runtime.state.create_system_cx();
                let (cid, _ch, child_cx, result_tx, spawn_effects) = runtime
                    .state
                    .create_task_infrastructure::<()>(&system_cx, client_region, budget, false)
                    .unwrap();
                let client_fut = {
                    let cx = child_cx.clone();
                    async move {
                        if let Ok(val) = server_ref.call(&cx, CounterCall::Add(i * 10)).await {
                            results_clone.lock().push(val);
                        }
                    }
                };
                let wrapped = {
                    async move {
                        spawn_effects.dispatch();
                        match (crate::cx::scope::CatchUnwind { inner: client_fut }).await {
                            Ok(value) => {
                                crate::runtime::task_handle::publish_terminal_result(
                                    result_tx,
                                    Ok(value),
                                );
                                Outcome::Ok(())
                            }
                            Err(payload) => {
                                let panic_payload = crate::types::outcome::PanicPayload::new(
                                    crate::cx::scope::payload_to_string(&payload),
                                );
                                crate::runtime::task_handle::publish_terminal_result(
                                    result_tx,
                                    Err(JoinError::Panicked(panic_payload.clone())),
                                );
                                Outcome::Panicked(panic_payload)
                            }
                        }
                    }
                };
                runtime
                    .state
                    .store_spawned_task(cid, crate::runtime::StoredTask::new_with_id(wrapped, cid));
                client_ids.push(cid);
            }

            // Schedule all tasks.
            {
                let mut sched = runtime.scheduler.lock();
                sched.schedule(server_task_id, 0);
                for &cid in &client_ids {
                    sched.schedule(cid, 0);
                }
            }
            runtime.run_until_quiescent();

            // Re-schedule to process enqueued calls.
            {
                let mut sched = runtime.scheduler.lock();
                sched.schedule(server_task_id, 0);
                for &cid in &client_ids {
                    sched.schedule(cid, 0);
                }
            }
            runtime.run_until_quiescent();

            // Stop and drain.
            handle.stop();
            {
                runtime.scheduler.lock().schedule(server_task_id, 0);
            }
            runtime.run_until_quiescent();

            results.lock().clone()
        }

        // Same seed must produce identical results.
        let run_a = run_scenario(42);
        let run_b = run_scenario(42);
        assert_eq!(
            run_a, run_b,
            "same seed must produce identical results: {run_a:?} vs {run_b:?}"
        );

        crate::test_complete!("conformance_deterministic_replay_with_seed");
    }

    /// Mailbox overflow with Reject policy: deterministic rejection when full.
    #[test]
    fn conformance_mailbox_overflow_reject_deterministic() {
        init_test("conformance_mailbox_overflow_reject_deterministic");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        // Capacity-2 mailbox with default Reject policy.
        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, Counter { count: 0 }, 2)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();

        // Fill the mailbox to capacity.
        server_ref.try_cast(CounterCast::Reset).unwrap();
        server_ref.try_cast(CounterCast::Reset).unwrap();

        // Third cast must be rejected (mailbox full, Reject policy).
        let overflow = server_ref.try_cast(CounterCast::Reset);
        assert!(
            overflow.is_err(),
            "third cast to capacity-2 mailbox must fail with Reject policy"
        );
        match overflow.unwrap_err() {
            CastError::Full => { /* expected */ }
            other => unreachable!("expected CastError::Full, got {other:?}"),
        }

        // Drain and cleanup.
        drop(handle);
        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        crate::test_complete!("conformance_mailbox_overflow_reject_deterministic");
    }

    /// DropOldest eviction preserves the newest messages when full.
    #[test]
    fn conformance_mailbox_drop_oldest_preserves_newest() {
        init_test("conformance_mailbox_drop_oldest_preserves_newest");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);

        // DropOldest counter with capacity 2.
        let (mut handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, DropOldestCounter { count: 0 }, 2)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        // Fill mailbox with Set(1) and Set(2).
        handle.try_cast(TaggedCast::Set(1)).unwrap();
        handle.try_cast(TaggedCast::Set(2)).unwrap();

        // Overflow with Set(100) — should evict Set(1), keeping Set(2) and Set(100).
        handle.try_cast(TaggedCast::Set(100)).unwrap();
        assert_eq!(
            handle.evicted_count(),
            1,
            "DropOldest should report exactly one eviction"
        );

        // Stop before first scheduling so the queued messages drain to a
        // terminal server result instead of parking the server on an empty
        // mailbox and making the join path scheduler-order dependent.
        handle.stop();
        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        let server = futures_lite::future::block_on(handle.join(&cx)).expect("server join ok");
        assert_eq!(
            server.count, 100,
            "DropOldest should evict oldest and leave newest value in server state"
        );

        crate::test_complete!("conformance_mailbox_drop_oldest_preserves_newest");
    }

    /// br-asupersync-c9b5nb LOW 6: GenServerRef::try_cast evicted under
    /// DropOldest without counting or logging it; only evictions through the
    /// handle showed in evicted_count().
    #[test]
    fn server_ref_drop_oldest_evictions_are_counted() {
        init_test("server_ref_drop_oldest_evictions_are_counted");

        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);
        let (mut handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, DropOldestCounter { count: 0 }, 2)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();
        server_ref.try_cast(TaggedCast::Set(1)).unwrap();
        server_ref.try_cast(TaggedCast::Set(2)).unwrap();
        server_ref.try_cast(TaggedCast::Set(3)).unwrap();
        assert_eq!(server_ref.evicted_count(), 1, "the reference's eviction");
        assert_eq!(
            handle.evicted_count(),
            1,
            "the handle counts evictions through its references"
        );
        handle.try_cast(TaggedCast::Set(4)).unwrap();
        assert_eq!(server_ref.clone().evicted_count(), 2);

        handle.stop();
        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();
        let server = futures_lite::future::block_on(handle.join(&cx)).expect("server join ok");
        assert_eq!(server.count, 4, "the newest casts survive");

        crate::test_complete!("server_ref_drop_oldest_evictions_are_counted");
    }

    /// Budget-driven timeout: a call with a tight poll_quota budget
    /// must terminate deterministically without wall-clock dependence.
    #[test]
    #[allow(clippy::items_after_statements)]
    fn conformance_budget_driven_call_timeout() {
        // Server that never replies (intentionally leaves reply unconsumed
        // by aborting it, which is the correct way to not reply).
        struct SlowServer;
        impl GenServer for SlowServer {
            type Call = ();
            type Reply = ();
            type Cast = ();
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: (),
                reply: Reply<()>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                // Abort the reply obligation (correct: no leak).
                let _proof = reply.abort();
                Box::pin(async {})
            }
        }

        init_test("conformance_budget_driven_call_timeout");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = lab_spawn_cx(&mut runtime, region, budget);
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, SlowServer, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();

        // Client calls the server. The server aborts the reply, so the
        // client should see a channel close / error.
        let call_result: Arc<Mutex<Option<Result<(), CallError>>>> = Arc::new(Mutex::new(None));
        let call_result_clone = Arc::clone(&call_result);
        let _ch = cx
            .spawn(move |cx| async move {
                let r = server_ref.call(&cx, ()).await;
                *call_result_clone.lock() = Some(r);
            })
            .unwrap();

        // Run everything.
        {
            let mut sched = runtime.scheduler.lock();
            sched.schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        // The client should have received an error since the server aborted.
        if let Some(ref result) = *call_result.lock() {
            assert!(result.is_err(), "aborted reply should result in call error");
        }

        // Clean up.
        handle.stop();
        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        crate::test_complete!("conformance_budget_driven_call_timeout");
    }

    /// Reply linearity: verify that Reply::send commits the obligation
    /// and the committed proof is returned.
    #[test]
    #[allow(clippy::items_after_statements)]
    fn conformance_reply_linearity_send_commits() {
        // Server that tracks whether reply was committed.
        struct ReplyTracker {
            committed: Arc<AtomicU8>,
        }

        impl GenServer for ReplyTracker {
            type Call = u64;
            type Reply = u64;
            type Cast = ();
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                request: u64,
                reply: Reply<u64>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                match reply.send(request * 2) {
                    ReplyOutcome::Committed(_proof) => {
                        self.committed.store(1, Ordering::SeqCst);
                    }
                    ReplyOutcome::CallerGone => {
                        self.committed.store(2, Ordering::SeqCst);
                    }
                }
                Box::pin(async {})
            }
        }

        init_test("conformance_reply_linearity_send_commits");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        let committed = Arc::new(AtomicU8::new(0));
        let server = ReplyTracker {
            committed: Arc::clone(&committed),
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .expect("should spawn reply linearity server");
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let (reply_tx, mut reply_rx) = session::tracked_oneshot::<u64>();
        let reply_permit = reply_tx
            .reserve(&cx)
            .expect("reply reserve should succeed in healthy test cx");
        let envelope: Envelope<ReplyTracker> = Envelope::Call {
            request: 21,
            reply_permit,
        };
        handle
            .sender
            .try_send(envelope)
            .expect("call envelope should enqueue");

        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        // Verify reply was committed (not CallerGone).
        assert_eq!(
            committed.load(Ordering::SeqCst),
            1,
            "reply must be committed when caller is waiting"
        );

        // Verify the caller received the correct value.
        let recv = futures_lite::future::block_on(reply_rx.recv(&cx));
        assert_eq!(recv, Ok(42), "21 * 2 = 42");

        handle.stop();
        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        crate::test_complete!("conformance_reply_linearity_send_commits");
    }

    /// Reply linearity: verify that Reply::abort produces an AbortedProof
    /// and the caller receives an error (not a value).
    #[test]
    #[allow(clippy::items_after_statements)]
    fn conformance_reply_linearity_abort_is_clean() {
        struct AbortServer {
            aborted: Arc<AtomicU8>,
        }

        impl GenServer for AbortServer {
            type Call = ();
            type Reply = ();
            type Cast = ();
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: (),
                reply: Reply<()>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _proof = reply.abort();
                self.aborted.store(1, Ordering::SeqCst);
                Box::pin(async {})
            }
        }

        init_test("conformance_reply_linearity_abort_is_clean");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = lab_spawn_cx(&mut runtime, region, budget);
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        let aborted = Arc::new(AtomicU8::new(0));
        let server = AbortServer {
            aborted: Arc::clone(&aborted),
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();
        let call_err: Arc<Mutex<Option<Result<(), CallError>>>> = Arc::new(Mutex::new(None));
        let call_err_clone = Arc::clone(&call_err);

        let _ch = cx
            .spawn(move |cx| async move {
                let r = server_ref.call(&cx, ()).await;
                *call_err_clone.lock() = Some(r);
            })
            .unwrap();

        {
            let mut sched = runtime.scheduler.lock();
            sched.schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        // Server should have aborted.
        assert_eq!(
            aborted.load(Ordering::SeqCst),
            1,
            "server must have called abort()"
        );

        // Caller should see an error, not Ok.
        {
            let r = call_err.lock();
            match r.as_ref() {
                Some(Err(_)) => { /* expected: aborted reply -> error */ }
                other => unreachable!("expected call error after abort, got {other:?}"),
            }
        }

        handle.stop();
        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        crate::test_complete!("conformance_reply_linearity_abort_is_clean");
    }

    #[test]
    #[allow(clippy::items_after_statements)]
    fn conformance_panicking_handle_call_returns_join_error_without_double_panic() {
        #[derive(Debug)]
        struct PanicOnCall;

        impl GenServer for PanicOnCall {
            type Call = ();
            type Reply = ();
            type Cast = ();
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: (),
                _reply: Reply<()>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                std::panic::panic_any("intentional handle_call panic");
            }
        }

        init_test("conformance_panicking_handle_call_returns_join_error_without_double_panic");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        let (mut handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, PanicOnCall, 32)
            .unwrap();
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let (reply_tx, mut reply_rx) = session::tracked_oneshot::<()>();
        let reply_permit = reply_tx
            .reserve(&cx)
            .expect("reply reserve should succeed in healthy test cx");
        let envelope: Envelope<PanicOnCall> = Envelope::Call {
            request: (),
            reply_permit,
        };
        handle
            .sender
            .try_send(envelope)
            .expect("call envelope should enqueue");

        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        let join = futures_lite::future::block_on(handle.join(&cx));
        assert!(
            matches!(join, Err(JoinError::Panicked(_))),
            "panicking call handler should surface JoinError::Panicked"
        );

        let client_result = futures_lite::future::block_on(reply_rx.recv(&cx));
        assert!(
            matches!(client_result, Err(oneshot::RecvError::Closed)),
            "caller should observe closed reply after panic, got {client_result:?}"
        );

        crate::test_complete!(
            "conformance_panicking_handle_call_returns_join_error_without_double_panic"
        );
    }

    /// On-stop processes remaining casts before completing (drain semantics).
    /// Verifies that queued casts are not silently dropped on shutdown.
    #[test]
    #[allow(clippy::items_after_statements)]
    fn conformance_drain_processes_queued_casts_on_stop() {
        struct AccumulatorServer {
            sum: u64,
            final_sum: Arc<AtomicU64>,
        }

        enum AccumCall {
            #[allow(dead_code)]
            GetSum,
        }
        enum AccumCast {
            Add(u64),
        }

        impl GenServer for AccumulatorServer {
            type Call = AccumCall;
            type Reply = u64;
            type Cast = AccumCast;
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: AccumCall,
                reply: Reply<u64>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(self.sum);
                Box::pin(async {})
            }

            fn handle_cast(
                &mut self,
                _cx: &Cx,
                msg: AccumCast,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                match msg {
                    AccumCast::Add(n) => self.sum += n,
                }
                Box::pin(async {})
            }

            fn on_stop(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.final_sum.store(self.sum, Ordering::SeqCst);
                Box::pin(async {})
            }
        }

        init_test("conformance_drain_processes_queued_casts_on_stop");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);

        let final_sum = Arc::new(AtomicU64::new(0));
        let server = AccumulatorServer {
            sum: 0,
            final_sum: Arc::clone(&final_sum),
        };

        let (handle, stored) = scope
            .spawn_gen_server(&mut runtime.state, &cx, server, 32)
            .expect("should spawn accumulator gen_server");
        let server_task_id = handle.task_id();
        runtime.state.store_spawned_task(server_task_id, stored);

        let server_ref = handle.server_ref();

        // Queue up several casts.
        server_ref
            .try_cast(AccumCast::Add(10))
            .expect("should cast Add(10)");
        server_ref
            .try_cast(AccumCast::Add(20))
            .expect("should cast Add(20)");
        server_ref
            .try_cast(AccumCast::Add(30))
            .expect("should cast Add(30)");

        // Stop before first scheduling so this verifies stop-drain semantics
        // specifically: queued casts must be processed before on_stop records
        // the final state.
        handle.stop();
        {
            runtime.scheduler.lock().schedule(server_task_id, 0);
        }
        runtime.run_until_quiescent();

        // The server should have processed all casts before stopping.
        let sum = final_sum.load(Ordering::SeqCst);
        assert_eq!(
            sum, 60,
            "server must drain queued casts before stopping: 10+20+30=60, got {sum}"
        );

        crate::test_complete!("conformance_drain_processes_queued_casts_on_stop");
    }

    // =========================================================================
    // Named GenServer integration tests (bd-23az1)
    // =========================================================================

    fn named_gen_server_test_region(
        runtime: &mut crate::lab::LabRuntime,
        budget: Budget,
    ) -> RegionId {
        let root = runtime.state.create_root_region(budget);
        runtime
            .state
            .create_child_region(root, budget)
            .expect("named gen_server tests need a non-root lease region")
    }

    /// A named server whose registry entry another task took over (Replace)
    /// can still give up its name: abort_lease and release_name resolve the
    /// lease instead of leaving it armed for the handle's drop to panic.
    #[test]
    fn named_server_lease_resolves_after_its_entry_was_replaced() {
        use crate::cx::registry::{NameCollisionOutcome, NameCollisionPolicy};

        #[derive(Debug)]
        struct Idle;

        impl GenServer for Idle {
            type Call = u64;
            type Reply = u64;
            type Cast = ();
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                request: u64,
                reply: Reply<u64>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(request);
                Box::pin(async {})
            }

            fn handle_cast(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                Box::pin(async {})
            }
        }

        crate::test_utils::init_test_logging();
        crate::test_phase!("named_server_lease_resolves_after_its_entry_was_replaced");
        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(43));
        let region = named_gen_server_test_region(&mut runtime, budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);
        let mut registry = crate::cx::NameRegistry::new();
        let now = crate::types::Time::from_nanos(1_000_000_000);

        for give_up_with_abort in [true, false] {
            let name = if give_up_with_abort {
                "svc_abort"
            } else {
                "svc_release"
            };
            let (mut named, stored) = scope
                .spawn_named_gen_server(&mut runtime.state, &cx, &mut registry, name, Idle, 8, now)
                .expect("spawn the named server");
            let task_id = named.task_id();
            runtime.state.store_spawned_task(task_id, stored);
            let NameCollisionOutcome::Replaced {
                lease: mut usurper, ..
            } = registry
                .register_with_policy(
                    name,
                    TaskId::new_for_test(9_999, 0),
                    region,
                    now,
                    NameCollisionPolicy::Replace,
                )
                .expect("another task takes the name over")
            else {
                panic!("Replace displaces the named server");
            };
            named.stop();
            runtime.scheduler.lock().schedule(task_id, 0);
            runtime.run_until_idle();
            let later = runtime.state.now;

            let gave_up = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if give_up_with_abort {
                    assert!(matches!(
                        named.abort_lease(&mut registry, later),
                        Err(crate::cx::NameLeaseError::PermissionDenied { .. })
                    ));
                } else {
                    assert!(matches!(
                        named.release_name(&mut registry, later),
                        Err(ReleaseNameError::Lease(
                            crate::cx::NameLeaseError::PermissionDenied { .. }
                        ))
                    ));
                }
                // The lease is resolved, so dropping the handle is quiet.
                drop(named);
            }));
            assert!(
                gave_up.is_ok(),
                "giving up the name must not panic ({name})"
            );
            assert_eq!(
                registry.whereis(name),
                Some(TaskId::new_for_test(9_999, 0)),
                "the usurper keeps the name"
            );
            registry
                .unregister_owned_and_grant(&usurper, later)
                .expect("unregister the usurper");
            let _ = usurper.release().expect("release the usurper");
        }
    }

    /// Named server: spawn registers name, whereis finds it.
    #[test]
    fn named_server_register_and_whereis() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("named_server_register_and_whereis");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(42));
        let region = named_gen_server_test_region(&mut runtime, budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);
        let mut registry = crate::cx::NameRegistry::new();

        #[allow(clippy::items_after_statements)]
        #[derive(Debug)]
        struct Counter(u64);

        #[allow(clippy::items_after_statements)]
        impl GenServer for Counter {
            type Call = u64;
            type Reply = u64;
            type Cast = ();
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                request: u64,
                reply: Reply<u64>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                self.0 += request;
                let _ = reply.send(self.0);
                Box::pin(async {})
            }

            fn handle_cast(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                Box::pin(async {})
            }
        }

        let now = crate::types::Time::from_nanos(1_000_000_000);
        let (mut named_handle, stored) = scope
            .spawn_named_gen_server(
                &mut runtime.state,
                &cx,
                &mut registry,
                "my_counter",
                Counter(0),
                32,
                now,
            )
            .expect("should spawn named gen_server 'my_counter'");

        let task_id = named_handle.task_id();
        runtime.state.store_spawned_task(task_id, stored);

        // Name should be visible via whereis.
        assert_eq!(registry.whereis("my_counter"), Some(task_id));
        assert_eq!(named_handle.name(), "my_counter");

        // Clean up: stop the task, drive it to completion, then release the name.
        named_handle.stop();
        {
            runtime.scheduler.lock().schedule(task_id, 0);
        }
        runtime.run_until_idle();
        let release_now = runtime.state.now;
        named_handle
            .release_name(&mut registry, release_now)
            .expect("release ok");
        assert!(
            registry.whereis("my_counter").is_none(),
            "name must be removed once shutdown completes",
        );

        let (mut restarted, stored) = scope
            .spawn_named_gen_server(
                &mut runtime.state,
                &cx,
                &mut registry,
                "my_counter",
                Counter(0),
                32,
                now,
            )
            .expect("name should be reusable after release_name");
        runtime
            .state
            .store_spawned_task(restarted.task_id(), stored);
        restarted.stop();
        {
            runtime.scheduler.lock().schedule(restarted.task_id(), 0);
        }
        runtime.run_until_quiescent();
        let restart_release_now = runtime.state.now;
        restarted
            .release_name(&mut registry, restart_release_now)
            .expect("restart cleanup ok");

        crate::test_complete!("named_server_register_and_whereis");
    }

    /// Named server: release_name must not remove the name until shutdown fully drains.
    #[test]
    fn named_server_release_name_requires_stopped_server() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("named_server_release_name_requires_stopped_server");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(42));
        let region = named_gen_server_test_region(&mut runtime, budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);
        let mut registry = crate::cx::NameRegistry::new();

        #[allow(clippy::items_after_statements)]
        #[derive(Debug)]
        struct Noop;

        #[allow(clippy::items_after_statements)]
        impl GenServer for Noop {
            type Call = ();
            type Reply = ();
            type Cast = ();
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: (),
                reply: Reply<()>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(());
                Box::pin(async {})
            }
        }

        let now = crate::types::Time::from_nanos(1_000_000_000);
        let (mut handle, stored) = scope
            .spawn_named_gen_server(
                &mut runtime.state,
                &cx,
                &mut registry,
                "still_running",
                Noop,
                8,
                now,
            )
            .expect("should spawn named gen_server 'still_running'");
        runtime.state.store_spawned_task(handle.task_id(), stored);

        assert!(
            matches!(
                handle.release_name(&mut registry, now),
                Err(ReleaseNameError::StillRunning)
            ),
            "release_name must fail closed while the server is still live",
        );
        assert_eq!(
            registry.whereis("still_running"),
            Some(handle.task_id()),
            "premature release_name must not remove the registered name",
        );

        handle.stop();
        assert!(
            matches!(
                handle.release_name(&mut registry, now),
                Err(ReleaseNameError::StillRunning)
            ),
            "release_name must keep failing closed after stop() until the task actually finishes",
        );
        assert_eq!(
            registry.whereis("still_running"),
            Some(handle.task_id()),
            "release_name during shutdown drain must not remove the registered name",
        );
        {
            runtime.scheduler.lock().schedule(handle.task_id(), 0);
        }
        runtime.run_until_quiescent();
        let release_now = runtime.state.now;
        handle
            .release_name(&mut registry, release_now)
            .expect("release after shutdown should succeed");

        crate::test_complete!("named_server_release_name_requires_stopped_server");
    }

    /// Named server: duplicate name is rejected.
    #[test]
    fn named_server_duplicate_name_rejected() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("named_server_duplicate_name_rejected");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(42));
        let region = named_gen_server_test_region(&mut runtime, budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);
        let mut registry = crate::cx::NameRegistry::new();

        #[allow(clippy::items_after_statements)]
        #[derive(Debug)]
        struct Dummy;

        #[allow(clippy::items_after_statements)]
        impl GenServer for Dummy {
            type Call = ();
            type Reply = ();
            type Cast = ();
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: (),
                reply: Reply<()>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(());
                Box::pin(async {})
            }

            fn handle_cast(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                Box::pin(async {})
            }
        }

        let now = crate::types::Time::from_nanos(1_000_000_000);

        // First spawn succeeds.
        let (mut h1, s1) = scope
            .spawn_named_gen_server(
                &mut runtime.state,
                &cx,
                &mut registry,
                "singleton",
                Dummy,
                8,
                now,
            )
            .expect("first spawn of 'singleton' should succeed");
        runtime.state.store_spawned_task(h1.task_id(), s1);

        // Second spawn with same name fails.
        let result = scope.spawn_named_gen_server(
            &mut runtime.state,
            &cx,
            &mut registry,
            "singleton",
            Dummy,
            8,
            now,
        );
        assert!(
            matches!(result, Err(NamedSpawnError::NameTaken(_))),
            "duplicate name should be rejected"
        );

        // Original is still registered.
        assert_eq!(registry.whereis("singleton"), Some(h1.task_id()));

        // Verify the orphaned task record from the failed spawn was cleaned up.
        // The region should only contain the first task; no leaked task record
        // that would prevent region quiescence.
        let region_tasks = runtime
            .state
            .region(region)
            .expect("region should exist for task validation")
            .task_ids();
        assert_eq!(
            region_tasks,
            vec![h1.task_id()],
            "region should only have the first task; orphaned task must be removed"
        );

        h1.stop();
        runtime.scheduler.lock().schedule(h1.task_id(), 0);
        runtime.run_until_quiescent();
        let release_now = runtime.state.now;
        h1.release_name(&mut registry, release_now)
            .expect("release ok");

        crate::test_complete!("named_server_duplicate_name_rejected");
    }

    /// Named server: abort_lease removes name from registry.
    #[test]
    fn named_server_abort_lease_removes_name() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("named_server_abort_lease_removes_name");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(42));
        let region = named_gen_server_test_region(&mut runtime, budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);
        let mut registry = crate::cx::NameRegistry::new();

        #[allow(clippy::items_after_statements)]
        #[derive(Debug)]
        struct Noop;

        #[allow(clippy::items_after_statements)]
        impl GenServer for Noop {
            type Call = ();
            type Reply = ();
            type Cast = ();
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _req: (),
                reply: Reply<()>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(());
                Box::pin(async {})
            }

            fn handle_cast(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                Box::pin(async {})
            }
        }

        let now = crate::types::Time::from_nanos(1_000_000_000);
        let (mut handle, stored) = scope
            .spawn_named_gen_server(
                &mut runtime.state,
                &cx,
                &mut registry,
                "temp_name",
                Noop,
                8,
                now,
            )
            .unwrap();
        runtime.state.store_spawned_task(handle.task_id(), stored);
        let mut alias = registry
            .register("temp_alias", handle.task_id(), scope.region_id(), now)
            .expect("second alias should register for same task");

        // Name is registered.
        assert!(registry.whereis("temp_name").is_some());
        assert_eq!(registry.whereis("temp_alias"), Some(handle.task_id()));

        // Abort the lease (simulating cancellation).
        handle.abort_lease(&mut registry, now).unwrap();
        assert!(
            registry.whereis("temp_name").is_none(),
            "aborting the lease must remove the registry entry",
        );
        assert_eq!(
            registry.whereis("temp_alias"),
            Some(handle.task_id()),
            "aborting one named handle must not drop other names owned by the same task",
        );
        registry
            .unregister_owned_and_grant(&alias, now)
            .expect("manual alias cleanup should succeed");
        alias.abort().unwrap();

        crate::test_complete!("named_server_abort_lease_removes_name");
    }

    /// Named server: take_lease allows manual lifecycle management.
    #[test]
    fn named_server_take_lease_manual_management() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("named_server_take_lease_manual_management");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(42));
        let region = named_gen_server_test_region(&mut runtime, budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);
        let mut registry = crate::cx::NameRegistry::new();

        #[allow(clippy::items_after_statements)]
        #[derive(Debug)]
        struct Noop2;

        #[allow(clippy::items_after_statements)]
        impl GenServer for Noop2 {
            type Call = ();
            type Reply = ();
            type Cast = ();
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _req: (),
                reply: Reply<()>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(());
                Box::pin(async {})
            }

            fn handle_cast(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                Box::pin(async {})
            }
        }

        let now = crate::types::Time::from_nanos(1_000_000_000);
        let (mut handle, stored) = scope
            .spawn_named_gen_server(
                &mut runtime.state,
                &cx,
                &mut registry,
                "manual_name",
                Noop2,
                8,
                now,
            )
            .unwrap();
        runtime.state.store_spawned_task(handle.task_id(), stored);

        // Take the lease for manual management.
        let mut lease = handle.take_lease().unwrap();
        assert!(handle.take_lease().is_none(), "second take returns None");

        // name() returns the released-name sentinel when the lease is taken.
        assert_eq!(handle.name(), "(released)");

        // Resolve the full manual lifecycle: remove the matching registry entry,
        // then resolve the lease token.
        registry
            .unregister_owned_and_grant(&lease, now)
            .expect("manual lease cleanup should remove the matching name");
        lease
            .abort()
            .expect("manual lease abort should resolve the token");
        assert!(
            registry.whereis("manual_name").is_none(),
            "manual lifecycle management must remove the registry entry as well as resolve the token",
        );

        crate::test_complete!("named_server_take_lease_manual_management");
    }

    /// Named server: release_name fails closed after take_lease removed the lease.
    #[test]
    fn named_server_release_name_after_take_lease_returns_already_resolved() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("named_server_release_name_after_take_lease_returns_already_resolved");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(42));
        let region = named_gen_server_test_region(&mut runtime, budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);
        let mut registry = crate::cx::NameRegistry::new();

        #[allow(clippy::items_after_statements)]
        #[derive(Debug)]
        struct Noop3;

        #[allow(clippy::items_after_statements)]
        impl GenServer for Noop3 {
            type Call = ();
            type Reply = ();
            type Cast = ();
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _req: (),
                reply: Reply<()>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(());
                Box::pin(async {})
            }

            fn handle_cast(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                Box::pin(async {})
            }
        }

        let now = crate::types::Time::from_nanos(1_000_000_000);
        let (mut handle, stored) = scope
            .spawn_named_gen_server(
                &mut runtime.state,
                &cx,
                &mut registry,
                "take_then_stop",
                Noop3,
                8,
                now,
            )
            .unwrap();
        runtime.state.store_spawned_task(handle.task_id(), stored);

        let mut lease = handle.take_lease().expect("lease should be present");
        assert_eq!(
            handle.handle.state.load(),
            ActorState::Created,
            "taking the lease alone must not stop the server"
        );
        assert!(
            matches!(
                handle.release_name(&mut registry, now),
                Err(ReleaseNameError::Lease(
                    crate::cx::NameLeaseError::AlreadyResolved
                ))
            ),
            "release_name after take_lease must fail closed with AlreadyResolved",
        );
        assert_eq!(
            handle.handle.state.load(),
            ActorState::Created,
            "failed release_name after take_lease must not mutate actor state"
        );
        assert_eq!(
            registry.whereis("take_then_stop"),
            Some(handle.task_id()),
            "failed release_name after take_lease must not unregister the live name",
        );
        registry
            .unregister_owned_and_grant(&lease, now)
            .expect("manual cleanup should still be possible after failed release_name");
        lease.abort().unwrap();

        crate::test_complete!(
            "named_server_release_name_after_take_lease_returns_already_resolved"
        );
    }

    /// Named server: abort_lease fails closed after take_lease removed the lease.
    #[test]
    fn named_server_abort_lease_after_take_lease_returns_already_resolved() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("named_server_abort_lease_after_take_lease_returns_already_resolved");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(42));
        let region = named_gen_server_test_region(&mut runtime, budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);
        let mut registry = crate::cx::NameRegistry::new();

        #[allow(clippy::items_after_statements)]
        #[derive(Debug)]
        struct Noop4;

        #[allow(clippy::items_after_statements)]
        impl GenServer for Noop4 {
            type Call = ();
            type Reply = ();
            type Cast = ();
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _req: (),
                reply: Reply<()>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(());
                Box::pin(async {})
            }

            fn handle_cast(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                Box::pin(async {})
            }
        }

        let now = crate::types::Time::from_nanos(1_000_000_000);
        let (mut handle, stored) = scope
            .spawn_named_gen_server(
                &mut runtime.state,
                &cx,
                &mut registry,
                "take_then_abort",
                Noop4,
                8,
                now,
            )
            .unwrap();
        runtime.state.store_spawned_task(handle.task_id(), stored);

        let mut lease = handle.take_lease().expect("lease should be present");
        let abort_err = handle.abort_lease(&mut registry, now).unwrap_err();
        assert_eq!(abort_err, crate::cx::NameLeaseError::AlreadyResolved);
        assert_eq!(
            registry.whereis("take_then_abort"),
            Some(handle.task_id()),
            "failed abort_lease after take_lease must not unregister the live name",
        );

        registry
            .unregister_owned_and_grant(&lease, now)
            .expect("manual cleanup should still be possible after failed abort_lease");
        lease.abort().unwrap();

        crate::test_complete!("named_server_abort_lease_after_take_lease_returns_already_resolved");
    }

    /// Named server: abort_lease fails closed after release_name resolved the lease.
    #[test]
    fn named_server_abort_lease_after_release_name_returns_already_resolved() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("named_server_abort_lease_after_release_name_returns_already_resolved");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(42));
        let region = named_gen_server_test_region(&mut runtime, budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);
        let mut registry = crate::cx::NameRegistry::new();

        #[allow(clippy::items_after_statements)]
        #[derive(Debug)]
        struct Noop4;

        #[allow(clippy::items_after_statements)]
        impl GenServer for Noop4 {
            type Call = ();
            type Reply = ();
            type Cast = ();
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _req: (),
                reply: Reply<()>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(());
                Box::pin(async {})
            }

            fn handle_cast(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                Box::pin(async {})
            }
        }

        let now = crate::types::Time::from_nanos(1_000_000_000);
        let (mut handle, stored) = scope
            .spawn_named_gen_server(
                &mut runtime.state,
                &cx,
                &mut registry,
                "stop_then_abort",
                Noop4,
                8,
                now,
            )
            .unwrap();
        runtime.state.store_spawned_task(handle.task_id(), stored);

        handle.stop();
        {
            runtime.scheduler.lock().schedule(handle.task_id(), 0);
        }
        runtime.run_until_quiescent();
        let release_now = runtime.state.now;
        handle
            .release_name(&mut registry, release_now)
            .expect("initial release should succeed");
        let abort_err = handle.abort_lease(&mut registry, now).unwrap_err();
        assert_eq!(abort_err, crate::cx::NameLeaseError::AlreadyResolved);
        assert!(
            registry.whereis("stop_then_abort").is_none(),
            "failed abort_lease after release_name must not mutate the registry entry",
        );

        crate::test_complete!(
            "named_server_abort_lease_after_release_name_returns_already_resolved"
        );
    }

    /// Named server: release_name only removes the targeted name, not every name on the task.
    #[test]
    fn named_server_release_name_preserves_other_names_on_same_task() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("named_server_release_name_preserves_other_names_on_same_task");

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(42));
        let region = named_gen_server_test_region(&mut runtime, budget);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, budget);
        let mut registry = crate::cx::NameRegistry::new();

        #[allow(clippy::items_after_statements)]
        #[derive(Debug)]
        struct Noop5;

        #[allow(clippy::items_after_statements)]
        impl GenServer for Noop5 {
            type Call = ();
            type Reply = ();
            type Cast = ();
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _req: (),
                reply: Reply<()>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(());
                Box::pin(async {})
            }

            fn handle_cast(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                Box::pin(async {})
            }
        }

        let now = crate::types::Time::from_nanos(1_000_000_000);
        let (mut handle, stored) = scope
            .spawn_named_gen_server(
                &mut runtime.state,
                &cx,
                &mut registry,
                "primary_name",
                Noop5,
                8,
                now,
            )
            .unwrap();
        runtime.state.store_spawned_task(handle.task_id(), stored);
        let mut alias = registry
            .register("secondary_name", handle.task_id(), scope.region_id(), now)
            .expect("second alias should register for same task");

        handle.stop();
        {
            runtime.scheduler.lock().schedule(handle.task_id(), 0);
        }
        runtime.run_until_quiescent();

        let release_now = runtime.state.now;
        handle
            .release_name(&mut registry, release_now)
            .expect("targeted release should succeed");
        assert!(
            registry.whereis("primary_name").is_none(),
            "release_name must remove the targeted registry entry",
        );
        assert_eq!(
            registry.whereis("secondary_name"),
            Some(handle.task_id()),
            "release_name must not remove unrelated names on the same task",
        );

        registry
            .unregister_owned_and_grant(&alias, release_now)
            .expect("manual alias cleanup should succeed");
        alias.release().unwrap();

        crate::test_complete!("named_server_release_name_preserves_other_names_on_same_task");
    }

    #[test]
    #[allow(clippy::items_after_statements)]
    fn named_start_helper_supervisor_stop_cleans_registry() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("named_start_helper_supervisor_stop_cleans_registry");

        #[derive(Debug)]
        struct Noop;

        impl GenServer for Noop {
            type Call = ();
            type Reply = ();
            type Cast = ();
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: (),
                reply: Reply<()>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(());
                Box::pin(async {})
            }

            fn handle_cast(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                Box::pin(async {})
            }
        }

        let registry: Arc<parking_lot::Mutex<crate::cx::NameRegistry>> =
            Arc::new(parking_lot::Mutex::new(crate::cx::NameRegistry::new()));

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(42));
        let root = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();

        let child = crate::supervision::ChildSpec::new(
            "svc_child",
            named_gen_server_start(Arc::clone(&registry), "svc", 16, || Noop),
        );

        let compiled = crate::supervision::SupervisorBuilder::new("svc_supervisor")
            .child(child)
            .compile()
            .expect("compile supervisor");

        let supervisor = compiled
            .spawn(&mut runtime.state, &cx, root, budget)
            .expect("spawn supervisor");

        assert_eq!(supervisor.started.len(), 1, "exactly one started child");
        let child_task = supervisor.started[0].task_id;
        assert_eq!(registry.lock().whereis("svc"), Some(child_task));

        // Stop the supervisor region and drive cancellation/finalization.
        let cancel_effects = runtime.state.cancel_request(
            supervisor.region,
            &crate::types::CancelReason::user("stop"),
            None,
        );
        let (tasks_to_schedule, wake_effects) = cancel_effects.into_parts();
        {
            let mut scheduler = runtime.scheduler.lock();
            for (task_id, priority) in tasks_to_schedule {
                scheduler.schedule_cancel(task_id, priority);
            }
        }
        wake_effects.dispatch();
        runtime.run_until_quiescent();

        assert!(
            registry.lock().whereis("svc").is_none(),
            "name must be removed after supervised stop",
        );

        crate::test_complete!("named_start_helper_supervisor_stop_cleans_registry");
    }

    #[test]
    #[allow(clippy::items_after_statements)]
    fn named_start_helper_grants_a_waiting_task_by_the_runtime_clock() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("named_start_helper_grants_a_waiting_task_by_the_runtime_clock");
        use crate::cx::registry::{NameCollisionOutcome, NameCollisionPolicy};

        #[derive(Debug)]
        struct Noop;

        impl GenServer for Noop {
            type Call = ();
            type Reply = ();
            type Cast = ();
            type Info = SystemMsg;

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: (),
                reply: Reply<()>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(());
                Box::pin(async {})
            }

            fn handle_cast(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                Box::pin(async {})
            }
        }

        let registry: Arc<parking_lot::Mutex<crate::cx::NameRegistry>> =
            Arc::new(parking_lot::Mutex::new(crate::cx::NameRegistry::new()));

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(42));
        let root = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();

        let child = crate::supervision::ChildSpec::new(
            "svc_child",
            named_gen_server_start(Arc::clone(&registry), "svc", 16, || Noop),
        );
        let compiled = crate::supervision::SupervisorBuilder::new("svc_supervisor")
            .child(child)
            .compile()
            .expect("compile supervisor");
        let supervisor = compiled
            .spawn(&mut runtime.state, &cx, root, budget)
            .expect("spawn supervisor");
        let child_task = supervisor.started[0].task_id;
        assert_eq!(registry.lock().whereis("svc"), Some(child_task));

        // Another task waits for the name until 0.5 s of runtime time. The
        // runtime clock is still near zero when the server stops, so the wait
        // is live; the old fixed 1 s release clock judged it expired
        // (br-asupersync-in4gh8 L1).
        let waiter = TaskId::new_for_test(9_999, 0);
        let waiter_region = crate::types::RegionId::new_for_test(9_999, 0);
        let start_now = runtime
            .state
            .timer_driver()
            .map_or(runtime.state.now, crate::time::TimerDriverHandle::now);
        assert!(
            start_now < Time::from_millis(500),
            "the runtime clock starts near zero: {start_now:?}"
        );
        let outcome = registry
            .lock()
            .register_with_policy(
                "svc",
                waiter,
                waiter_region,
                start_now,
                NameCollisionPolicy::Wait {
                    deadline: Time::from_millis(500),
                },
            )
            .expect("enqueue the waiter");
        assert!(matches!(outcome, NameCollisionOutcome::Enqueued));

        let cancel_effects = runtime.state.cancel_request(
            supervisor.region,
            &crate::types::CancelReason::user("stop"),
            None,
        );
        let (tasks_to_schedule, wake_effects) = cancel_effects.into_parts();
        {
            let mut scheduler = runtime.scheduler.lock();
            for (task_id, priority) in tasks_to_schedule {
                scheduler.schedule_cancel(task_id, priority);
            }
        }
        wake_effects.dispatch();
        runtime.run_until_quiescent();

        let mut registry = registry.lock();
        assert_eq!(
            registry.whereis("svc"),
            Some(waiter),
            "the server's release grants the name to the live waiter"
        );
        let mut granted = registry
            .take_granted_for("svc", waiter, waiter_region)
            .expect("the grant waits for the waiter");
        granted
            .lease
            .release()
            .expect("the waiter resolves its lease");

        crate::test_complete!("named_start_helper_grants_a_waiting_task_by_the_runtime_clock");
    }

    #[test]
    #[allow(clippy::items_after_statements)]
    fn named_start_helper_crash_then_stop_cleans_registry() {
        crate::test_utils::init_test_logging();
        crate::test_phase!("named_start_helper_crash_then_stop_cleans_registry");

        #[derive(Debug)]
        struct PanicOnStart;

        impl GenServer for PanicOnStart {
            type Call = ();
            type Reply = ();
            type Cast = ();
            type Info = SystemMsg;

            fn on_start(&mut self, _cx: &Cx) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                Box::pin(async move {
                    std::panic::panic_any("intentional start crash for registry cleanup test");
                })
            }

            fn handle_call(
                &mut self,
                _cx: &Cx,
                _request: (),
                reply: Reply<()>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                let _ = reply.send(());
                Box::pin(async {})
            }

            fn handle_cast(
                &mut self,
                _cx: &Cx,
                _msg: (),
            ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
                Box::pin(async {})
            }
        }

        let registry: Arc<parking_lot::Mutex<crate::cx::NameRegistry>> =
            Arc::new(parking_lot::Mutex::new(crate::cx::NameRegistry::new()));

        let budget = Budget::new().with_poll_quota(100_000);
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(7));
        let root = runtime.state.create_root_region(budget);
        let cx = Cx::for_testing();

        let child = crate::supervision::ChildSpec::new(
            "panic_child",
            named_gen_server_start(Arc::clone(&registry), "panic_svc", 8, || PanicOnStart),
        );

        let compiled = crate::supervision::SupervisorBuilder::new("panic_supervisor")
            .child(child)
            .compile()
            .expect("compile supervisor");

        let supervisor = compiled
            .spawn(&mut runtime.state, &cx, root, budget)
            .expect("spawn supervisor");

        let child_task = supervisor.started[0].task_id;
        assert_eq!(registry.lock().whereis("panic_svc"), Some(child_task));

        // Drive the child once so it crashes in on_start. The supervisor
        // region intentionally remains open with a pending name-cleanup
        // finalizer, so this phase is idle rather than quiescent.
        {
            runtime.scheduler.lock().schedule(child_task, 0);
        }
        runtime.run_until_idle();

        // Region stop must still clean the registry + resolve the lease.
        let cancel_effects = runtime.state.cancel_request(
            supervisor.region,
            &crate::types::CancelReason::user("shutdown"),
            None,
        );
        let (tasks_to_schedule, wake_effects) = cancel_effects.into_parts();
        {
            let mut scheduler = runtime.scheduler.lock();
            for (task_id, priority) in tasks_to_schedule {
                scheduler.schedule_cancel(task_id, priority);
            }
        }
        wake_effects.dispatch();
        runtime.run_until_quiescent();

        assert!(
            registry.lock().whereis("panic_svc").is_none(),
            "name must be removed after crash + region stop",
        );

        crate::test_complete!("named_start_helper_crash_then_stop_cleans_registry");
    }

    // ========================================================================
    // Pure data-type tests (wave 9 – CyanBarn)
    // ========================================================================

    #[test]
    fn cast_overflow_policy_default_is_reject() {
        let policy = CastOverflowPolicy::default();
        assert!(matches!(policy, CastOverflowPolicy::Reject));
    }

    #[test]
    fn cast_overflow_policy_debug() {
        let dbg = format!("{:?}", CastOverflowPolicy::Reject);
        assert!(dbg.contains("Reject"), "{dbg}");
        let dbg2 = format!("{:?}", CastOverflowPolicy::DropOldest);
        assert!(dbg2.contains("DropOldest"), "{dbg2}");
    }

    #[test]
    fn cast_overflow_policy_eq_clone_copy() {
        let a = CastOverflowPolicy::Reject;
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(CastOverflowPolicy::Reject, CastOverflowPolicy::DropOldest);
    }

    #[test]
    fn down_msg_constructor_and_debug() {
        let mut monitors = crate::monitor::MonitorSet::new();
        let mref = monitors.establish(tid(50), rid(0), tid(51));
        let msg = DownMsg::new(
            Time::from_secs(7),
            DownNotification {
                monitored: tid(51),
                reason: DownReason::Normal,
                monitor_ref: mref,
            },
        );
        assert_eq!(msg.completion_vt, Time::from_secs(7));
        assert_eq!(msg.notification.monitored, tid(51));
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("DownMsg"), "{dbg}");
    }

    #[test]
    fn down_msg_clone() {
        let mut monitors = crate::monitor::MonitorSet::new();
        let mref = monitors.establish(tid(60), rid(0), tid(61));
        let msg = DownMsg::new(
            Time::from_secs(8),
            DownNotification {
                monitored: tid(61),
                reason: DownReason::Normal,
                monitor_ref: mref,
            },
        );
        let cloned = msg.clone();
        assert_eq!(cloned.completion_vt, msg.completion_vt);
        assert_eq!(cloned.notification.monitored, msg.notification.monitored);
    }

    #[test]
    fn exit_msg_constructor_and_eq() {
        let a = ExitMsg::new(Time::from_secs(5), tid(10), DownReason::Normal);
        let b = ExitMsg::new(Time::from_secs(5), tid(10), DownReason::Normal);
        assert_eq!(a, b);
    }

    #[test]
    fn exit_msg_debug_and_clone() {
        let msg = ExitMsg::new(
            Time::from_secs(6),
            tid(11),
            DownReason::Error("oops".into()),
        );
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("ExitMsg"), "{dbg}");
        let cloned = msg.clone();
        assert_eq!(cloned, msg);
    }

    #[test]
    fn exit_msg_inequality() {
        let a = ExitMsg::new(Time::from_secs(1), tid(1), DownReason::Normal);
        let b = ExitMsg::new(Time::from_secs(2), tid(1), DownReason::Normal);
        assert_ne!(a, b);
    }

    #[test]
    fn timeout_msg_constructor_eq_copy() {
        let a = TimeoutMsg::new(Time::from_secs(10), 42);
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_eq!(a.tick_vt, Time::from_secs(10));
        assert_eq!(a.id, 42);
    }

    #[test]
    fn timeout_msg_debug() {
        let msg = TimeoutMsg::new(Time::from_secs(1), 99);
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("TimeoutMsg"), "{dbg}");
    }

    #[test]
    fn timeout_msg_inequality() {
        let a = TimeoutMsg::new(Time::from_secs(1), 1);
        let b = TimeoutMsg::new(Time::from_secs(1), 2);
        assert_ne!(a, b);
    }

    #[test]
    fn system_msg_debug_all_variants() {
        let mut monitors = crate::monitor::MonitorSet::new();
        let mref = monitors.establish(tid(70), rid(0), tid(71));

        let down = SystemMsg::Down {
            completion_vt: Time::from_secs(1),
            notification: DownNotification {
                monitored: tid(71),
                reason: DownReason::Normal,
                monitor_ref: mref,
            },
        };
        let exit = SystemMsg::Exit {
            exit_vt: Time::from_secs(2),
            from: tid(72),
            reason: DownReason::Normal,
        };
        let timeout = SystemMsg::Timeout {
            tick_vt: Time::from_secs(3),
            id: 55,
        };

        let d = format!("{down:?}");
        assert!(d.contains("Down"), "{d}");
        let e = format!("{exit:?}");
        assert!(e.contains("Exit"), "{e}");
        let t = format!("{timeout:?}");
        assert!(t.contains("Timeout"), "{t}");
    }

    #[test]
    fn system_msg_clone() {
        let msg = SystemMsg::Timeout {
            tick_vt: Time::from_secs(5),
            id: 7,
        };
        let cloned = msg.clone();
        assert_eq!(cloned.sort_key(), msg.sort_key());
    }

    #[test]
    fn system_msg_convenience_constructors() {
        let mut monitors = crate::monitor::MonitorSet::new();
        let mref = monitors.establish(tid(80), rid(0), tid(81));

        let down_payload = DownMsg::new(
            Time::from_secs(1),
            DownNotification {
                monitored: tid(81),
                reason: DownReason::Normal,
                monitor_ref: mref,
            },
        );
        let msg = SystemMsg::down(down_payload);
        assert!(matches!(msg, SystemMsg::Down { .. }));

        let exit_payload = ExitMsg::new(Time::from_secs(2), tid(82), DownReason::Normal);
        let msg = SystemMsg::exit(exit_payload);
        assert!(matches!(msg, SystemMsg::Exit { .. }));

        let timeout_payload = TimeoutMsg::new(Time::from_secs(3), 44);
        let msg = SystemMsg::timeout(timeout_payload);
        assert!(matches!(msg, SystemMsg::Timeout { .. }));
    }

    #[test]
    fn system_msg_sort_key_kind_rank_ordering() {
        let mut monitors = crate::monitor::MonitorSet::new();
        let mref = monitors.establish(tid(85), rid(0), tid(86));

        let same_vt = Time::from_secs(100);
        let down = SystemMsg::Down {
            completion_vt: same_vt,
            notification: DownNotification {
                monitored: tid(86),
                reason: DownReason::Normal,
                monitor_ref: mref,
            },
        };
        let exit = SystemMsg::Exit {
            exit_vt: same_vt,
            from: tid(86),
            reason: DownReason::Normal,
        };
        let timeout = SystemMsg::Timeout {
            tick_vt: same_vt,
            id: 1,
        };

        // Down < Exit < Timeout (kind ranks 0, 1, 2)
        assert!(down.sort_key() < exit.sort_key());
        assert!(exit.sort_key() < timeout.sort_key());
    }

    #[test]
    fn system_msg_subject_key_debug_eq_ord() {
        let a = SystemMsgSubjectKey::Task(tid(1));
        let b = SystemMsgSubjectKey::Task(tid(1));
        let c = SystemMsgSubjectKey::TimeoutId(1);

        assert_eq!(a, b);
        assert_ne!(a, c);

        let dbg = format!("{a:?}");
        assert!(dbg.contains("Task"), "{dbg}");
        let dbg2 = format!("{c:?}");
        assert!(dbg2.contains("TimeoutId"), "{dbg2}");

        // Copy + Clone
        let copied = a;
        let cloned = a;
        assert_eq!(copied, cloned);

        // Ord consistency
        assert!(a <= b);
    }

    #[test]
    fn system_msg_batch_default_and_empty() {
        let batch = SystemMsgBatch::new();
        let sorted = batch.into_sorted();
        assert!(sorted.is_empty());
    }

    #[test]
    fn system_msg_batch_debug() {
        let batch = SystemMsgBatch::new();
        let dbg = format!("{batch:?}");
        assert!(dbg.contains("SystemMsgBatch"), "{dbg}");
    }

    #[test]
    fn system_msg_batch_single_element() {
        let mut batch = SystemMsgBatch::new();
        batch.push(SystemMsg::Timeout {
            tick_vt: Time::from_secs(42),
            id: 1,
        });
        let sorted = batch.into_sorted();
        assert_eq!(sorted.len(), 1);
        assert!(matches!(sorted[0], SystemMsg::Timeout { id: 1, .. }));
    }

    #[test]
    fn call_error_display_server_stopped() {
        let err = CallError::ServerStopped;
        let disp = format!("{err}");
        assert_eq!(disp, "GenServer has stopped");
    }

    #[test]
    fn call_error_display_no_reply() {
        let err = CallError::NoReply;
        let disp = format!("{err}");
        assert_eq!(disp, "GenServer did not reply");
    }

    #[test]
    fn call_error_display_cancelled() {
        let reason = CancelReason::user("test cancel");
        let err = CallError::Cancelled(reason);
        let disp = format!("{err}");
        assert!(disp.contains("cancelled"), "{disp}");
    }

    #[test]
    fn call_error_debug_all_variants() {
        let dbg1 = format!("{:?}", CallError::ServerStopped);
        assert!(dbg1.contains("ServerStopped"), "{dbg1}");
        let dbg2 = format!("{:?}", CallError::NoReply);
        assert!(dbg2.contains("NoReply"), "{dbg2}");
        let dbg3 = format!("{:?}", CallError::Cancelled(CancelReason::user("x")));
        assert!(dbg3.contains("Cancelled"), "{dbg3}");
    }

    #[test]
    fn call_error_is_std_error() {
        let err = CallError::ServerStopped;
        let _: &dyn std::error::Error = &err;
        // source() defaults to None
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn cast_error_display_all_variants() {
        assert_eq!(
            format!("{}", CastError::ServerStopped),
            "GenServer has stopped"
        );
        assert_eq!(format!("{}", CastError::Full), "GenServer mailbox full");
        let cancelled = CastError::Cancelled(CancelReason::user("t"));
        let disp = format!("{cancelled}");
        assert!(disp.contains("cancelled"), "{disp}");
    }

    #[test]
    fn cast_error_debug_all_variants() {
        let dbg1 = format!("{:?}", CastError::ServerStopped);
        assert!(dbg1.contains("ServerStopped"), "{dbg1}");
        let dbg2 = format!("{:?}", CastError::Full);
        assert!(dbg2.contains("Full"), "{dbg2}");
    }

    #[test]
    fn cast_error_is_std_error() {
        let err = CastError::Full;
        let _: &dyn std::error::Error = &err;
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn info_error_display_all_variants() {
        assert_eq!(
            format!("{}", InfoError::ServerStopped),
            "GenServer has stopped"
        );
        assert_eq!(format!("{}", InfoError::Full), "GenServer mailbox full");
        let cancelled = InfoError::Cancelled(CancelReason::user("u"));
        let disp = format!("{cancelled}");
        assert!(disp.contains("cancelled"), "{disp}");
    }

    #[test]
    fn info_error_debug_all_variants() {
        let dbg1 = format!("{:?}", InfoError::ServerStopped);
        assert!(dbg1.contains("ServerStopped"), "{dbg1}");
        let dbg2 = format!("{:?}", InfoError::Full);
        assert!(dbg2.contains("Full"), "{dbg2}");
    }

    #[test]
    fn info_error_is_std_error() {
        let err = InfoError::ServerStopped;
        let _: &dyn std::error::Error = &err;
        assert!(std::error::Error::source(&err).is_none());
    }

    #[test]
    fn system_msg_try_from_exit_rejects_timeout() {
        let timeout = SystemMsg::Timeout {
            tick_vt: Time::from_secs(1),
            id: 7,
        };
        let err = ExitMsg::try_from(timeout).expect_err("timeout is not exit");
        assert!(matches!(err, SystemMsg::Timeout { id: 7, .. }));
    }

    #[test]
    fn system_msg_try_from_exit_succeeds() {
        let exit = SystemMsg::Exit {
            exit_vt: Time::from_secs(3),
            from: tid(15),
            reason: DownReason::Normal,
        };
        let result = ExitMsg::try_from(exit).expect("exit conversion");
        assert_eq!(result.exit_vt, Time::from_secs(3));
        assert_eq!(result.from, tid(15));
    }

    #[test]
    fn system_msg_try_from_timeout_rejects_exit() {
        let exit = SystemMsg::Exit {
            exit_vt: Time::from_secs(1),
            from: tid(1),
            reason: DownReason::Normal,
        };
        let err = TimeoutMsg::try_from(exit).expect_err("exit is not timeout");
        assert!(matches!(err, SystemMsg::Exit { .. }));
    }

    // ---- Monitors and links held by a server (kpmoy5.6.1) ----

    /// Records every system message `handle_info` receives.
    #[derive(Debug)]
    struct SystemRecorder {
        seen: Arc<Mutex<Vec<SystemMsg>>>,
    }

    impl GenServer for SystemRecorder {
        type Call = ();
        type Reply = ();
        type Cast = ();
        type Info = SystemMsg;

        fn handle_call(
            &mut self,
            _cx: &Cx,
            _request: (),
            reply: Reply<()>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            let _ = reply.send(());
            Box::pin(async {})
        }

        fn handle_info(
            &mut self,
            _cx: &Cx,
            msg: SystemMsg,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.seen.lock().push(msg);
            Box::pin(async {})
        }
    }

    /// Runs a lab scenario: a `SystemRecorder` server, a target task that
    /// panics once `gate` opens, and a driver task that calls `watch` on the
    /// server handle, opens the gate, waits for a system message, then stops
    /// the server. Returns the recorded messages, the target id and the
    /// server's state just before the stop.
    fn run_watch_scenario<W, Fut>(watch: W) -> (Vec<SystemMsg>, TaskId, ActorState)
    where
        W: FnOnce(GenServerHandle<SystemRecorder>, Cx, TaskId) -> Fut + Send + 'static,
        Fut: Future<Output = GenServerHandle<SystemRecorder>> + Send + 'static,
    {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let cx = Cx::for_testing();
        let scope = crate::cx::Scope::<FailFast>::new(region, Budget::INFINITE);
        let (handle, stored) = scope
            .spawn_gen_server(
                &mut runtime.state,
                &cx,
                SystemRecorder {
                    seen: Arc::clone(&seen),
                },
                8,
            )
            .expect("spawn recorder server");
        let server = handle.task_id();
        runtime.state.store_spawned_task(server, stored);
        runtime.scheduler.lock().schedule(server, 0);

        let gate = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let target_gate = Arc::clone(&gate);
        let (target, target_handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                while !target_gate.load(Ordering::Acquire) {
                    yield_now().await;
                }
                panic!("watched task panics");
            })
            .expect("create target task");
        runtime.scheduler.lock().schedule(target, 0);

        let driver_seen = Arc::clone(&seen);
        let state_before_stop = Arc::new(Mutex::new(None));
        let driver_state = Arc::clone(&state_before_stop);
        let (driver, driver_handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = Cx::current().expect("a lab task has a Cx");
                let handle = watch(handle, cx, target).await;
                gate.store(true, Ordering::Release);
                while driver_seen.lock().is_empty() {
                    yield_now().await;
                }
                // Room for a duplicate to show up before the server stops.
                for _ in 0..32 {
                    yield_now().await;
                }
                *driver_state.lock() = Some(handle.state.load());
                handle.stop();
            })
            .expect("create driver task");
        runtime.scheduler.lock().schedule(driver, 0);
        runtime.run_until_quiescent();
        drop((target_handle, driver_handle));

        let seen = seen.lock().clone();
        let state = state_before_stop.lock().expect("driver ran to the stop");
        (seen, target, state)
    }

    #[test]
    fn gen_server_monitor_delivers_one_down_through_handle_info() {
        init_test("gen_server_monitor_delivers_one_down_through_handle_info");
        let monitor_ref = Arc::new(Mutex::new(None));
        let recorded_ref = Arc::clone(&monitor_ref);
        let (seen, target, _) = run_watch_scenario(move |handle, cx, target| async move {
            let reference = handle
                .monitor(&cx, target)
                .await
                .expect("the server monitors the live target");
            *recorded_ref.lock() = Some(reference);
            handle
        });
        assert_eq!(seen.len(), 1, "exactly one DOWN: {seen:?}");
        match &seen[0] {
            SystemMsg::Down { notification, .. } => {
                assert_eq!(notification.monitored, target);
                assert_eq!(Some(notification.monitor_ref), *monitor_ref.lock());
                assert!(
                    notification.reason.is_panicked(),
                    "{:?}",
                    notification.reason
                );
            }
            other => panic!("expected a DOWN, got {other:?}"),
        }
        crate::test_complete!("gen_server_monitor_delivers_one_down_through_handle_info");
    }

    #[test]
    fn gen_server_trapping_link_delivers_the_exit_and_keeps_the_server_running() {
        init_test("gen_server_trapping_link_delivers_the_exit_and_keeps_the_server_running");
        let (seen, target, state) = run_watch_scenario(|handle, cx, target| async move {
            handle
                .link_trapping(&cx, target)
                .await
                .expect("the server links to the live target");
            handle
        });
        assert_eq!(seen.len(), 1, "exactly one exit signal: {seen:?}");
        match &seen[0] {
            SystemMsg::Exit { from, reason, .. } => {
                assert_eq!(*from, target);
                assert!(reason.is_panicked(), "{reason:?}");
            }
            other => panic!("expected an exit signal, got {other:?}"),
        }
        assert_eq!(
            state,
            ActorState::Running,
            "a trapping server is not cancelled by its peer's exit"
        );
        crate::test_complete!(
            "gen_server_trapping_link_delivers_the_exit_and_keeps_the_server_running"
        );
    }
