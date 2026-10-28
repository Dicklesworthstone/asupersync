    use super::*;
    use crate::cx::Cx;
    use crate::lab::{LabConfig, LabRuntime};
    use crate::record::TaskRecord;
    use crate::runtime::reactor::LabReactor;
    #[cfg(unix)]
    use crate::runtime::reactor::{Event, Interest, Reactor};
    use crate::test_utils::init_test_logging;
    use crate::time::sleep;
    use crate::trace::{TraceEvent, TraceEventKind};
    use crate::types::{Budget, CancelReason, CxInner, RegionId, TaskId, Time};
    use parking_lot::RwLock;
    #[cfg(unix)]
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    static CURRENT_HANDLE_DTOR_STATE: AtomicU8 = AtomicU8::new(0);

    thread_local! {
        static CURRENT_HANDLE_DTOR_PROBE: CurrentHandleDtorProbe = const { CurrentHandleDtorProbe };
    }

    struct CurrentHandleDtorProbe;

    impl Drop for CurrentHandleDtorProbe {
        fn drop(&mut self) {
            let state = match CURRENT_RUNTIME_HANDLE.try_with(|cell| cell.borrow().clone()) {
                Ok(Some(_)) => 1,
                Ok(None) => 2,
                Err(_) => {
                    if Runtime::current_handle().is_none() {
                        3
                    } else {
                        4
                    }
                }
            };
            CURRENT_HANDLE_DTOR_STATE.store(state, Ordering::SeqCst);
        }
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn panic_payload_to_string(payload: Box<dyn std::any::Any + Send>) -> String {
        match payload.downcast::<String>() {
            Ok(message) => *message,
            Err(payload) => payload.downcast::<&'static str>().map_or_else(
                |_| "<non-string panic payload>".to_string(),
                |message| (*message).to_string(),
            ),
        }
    }

    #[test]
    fn worker_teardown_retains_job_when_first_reaper_spawn_is_refused() {
        let payload = Arc::new(());
        let weak_payload = Arc::downgrade(&payload);
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let mut attempts = 0;
        let mut reaper = None;

        RuntimeInner::finish_teardown_with_spawner(
            move || {
                drop(payload);
                finished_tx.send(()).expect("observe completed teardown");
            },
            |job| {
                attempts += 1;
                if attempts == 1 {
                    drop(job);
                    assert!(
                        weak_payload.upgrade().is_some(),
                        "a refused spawn must leave the teardown payload owned"
                    );
                    assert!(finished_rx.try_recv().is_err());
                    Err(io::Error::other("injected thread creation refusal"))
                } else {
                    let handle = std::thread::Builder::new().spawn(job)?;
                    reaper = Some(handle);
                    Ok(())
                }
            },
        );

        assert_eq!(attempts, 2);
        reaper.unwrap().join().expect("teardown thread completes");
        finished_rx.try_recv().expect("teardown ran exactly once");
        assert!(finished_rx.try_recv().is_err());
        assert!(weak_payload.upgrade().is_none());
    }

    #[test]
    fn runtime_teardown_releases_parked_task_join_barriers() {
        struct Retired(Arc<AtomicBool>);
        impl Drop for Retired {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        struct JoinWake {
            signal: std::sync::mpsc::SyncSender<()>,
            state: Arc<crate::sync::ContendedMutex<RuntimeState>>,
        }
        impl std::task::Wake for JoinWake {
            fn wake(self: Arc<Self>) {
                let state = self
                    .state
                    .try_lock()
                    .expect("join wake must run outside the state lock");
                assert!(
                    state.tasks.is_empty(),
                    "stopped tasks must be detached even when state is retained"
                );
                drop(state);
                let _ = self.signal.try_send(());
            }
        }

        for (workers, sharded) in [(1, false), (1, true), (2, false), (2, true)] {
            for background in [false, true] {
                let runtime = if workers == 1 {
                    RuntimeBuilder::current_thread()
                        .with_sharded_state(sharded)
                        .build()
                        .unwrap()
                } else {
                    RuntimeBuilder::multi_thread()
                        .worker_threads(workers)
                        .with_sharded_state(sharded)
                        .build()
                        .unwrap()
                };
                let retired = Arc::new(AtomicBool::new(false));
                let parked = Arc::new(AtomicBool::new(false));
                let changed = Arc::new(crate::sync::Notify::new());
                let mut handle = runtime.block_on(async {
                    let cx = Cx::current().unwrap();
                    let child_retired = Arc::clone(&retired);
                    let child_parked = Arc::clone(&parked);
                    let child_changed = Arc::clone(&changed);
                    let handle = cx
                        .spawn(move |_| async move {
                            let _retired = Retired(child_retired);
                            std::future::poll_fn(|_| {
                                if !child_parked.swap(true, Ordering::AcqRel) {
                                    child_changed.notify_waiters();
                                }
                                Poll::<()>::Pending
                            })
                            .await;
                        })
                        .unwrap();
                    crate::time::timeout(
                        cx.now(),
                        Duration::from_secs(5),
                        changed.wait_until(|| parked.load(Ordering::Acquire)),
                    )
                    .await
                    .expect("child must park without waking itself");
                    handle
                });
                let (woken, wake) = std::sync::mpsc::sync_channel(1);
                let waker = Waker::from(Arc::new(JoinWake {
                    signal: woken,
                    state: Arc::clone(&runtime.inner.state),
                }));
                assert!(
                    handle
                        .poll_join(&mut Context::from_waker(&waker))
                        .is_pending()
                );
                assert!(!handle.is_finished());
                assert!(!retired.load(Ordering::Acquire));
                let started = Instant::now();
                eprintln!(
                    "teardown_join workers={workers} sharded={sharded} background={background} task={:?} parked=true trigger=shutdown",
                    handle.task_id()
                );
                if background {
                    let _ = runtime.shutdown_timeout(Duration::ZERO);
                } else {
                    drop(runtime);
                }
                let wake_result = wake.recv_timeout(Duration::from_secs(5));
                eprintln!(
                    "teardown_join workers={workers} sharded={sharded} background={background} wake={wake_result:?} retired={} elapsed={:?}",
                    retired.load(Ordering::Acquire),
                    started.elapsed()
                );
                wake_result.expect("runtime teardown must wake the parked join consumer");
                assert!(
                    retired.load(Ordering::Acquire),
                    "task future must retire before join wakes"
                );
                assert!(
                    handle.is_finished(),
                    "retired task must be observably finished"
                );
                let observer = RuntimeBuilder::current_thread().build().unwrap();
                let result = observer.block_on(async {
                    let cx = Cx::current().unwrap();
                    crate::time::timeout(cx.now(), Duration::from_secs(5), handle.join(&cx))
                        .await
                        .expect("a different runtime must observe the terminal join")
                });
                assert!(
                    matches!(&result, Err(crate::runtime::task_handle::JoinError::Cancelled(reason))
                    if reason.kind == crate::types::CancelKind::Shutdown),
                    "{result:?}"
                );
            }
        }
    }

    #[test]
    fn shutdown_timeout_stays_bounded_when_reaper_spawn_is_refused() {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build runtime");
        let runtime_inner = Arc::downgrade(&runtime.inner);
        let completed =
            runtime.shutdown_timeout_with_spawner(Duration::from_secs(60), |_job| false);

        assert!(!completed, "a refused reaper spawn is not a clean teardown");
        assert!(
            runtime_inner.upgrade().is_some(),
            "spawn refusal must retain the runtime instead of dropping it inline"
        );
    }

    #[test]
    fn shutdown_completion_reports_late_teardown_after_deadline() {
        let completion = RuntimeShutdownCompletion::new();
        let started = Instant::now();
        std::thread::sleep(Duration::from_millis(20));
        completion.signal();

        assert!(
            !completion.wait_with_budget(started, Duration::from_millis(5)),
            "completion observed after the caller's deadline must remain a timeout"
        );
        assert!(
            completion.wait_timeout(Duration::ZERO),
            "a later caller must still observe already-completed teardown"
        );
    }

    #[test]
    fn shutdown_timeout_reports_incomplete_while_a_strong_clone_remains() {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build runtime");
        let runtime_inner = Arc::downgrade(&runtime.inner);
        let shutdown_complete = Arc::clone(&runtime.inner.shutdown_completion);
        let retained = runtime.clone();

        assert!(
            !runtime.shutdown_timeout(Duration::ZERO),
            "shutdown cannot report complete while another Runtime owns the inner state"
        );

        drop(retained);
        assert!(
            shutdown_complete.wait_timeout(Duration::from_secs(10)),
            "the reaper must finish after the last external owner is released"
        );
        assert!(runtime_inner.upgrade().is_none());
    }

    #[test]
    fn repeated_shutdown_timeout_calls_share_one_reaper() {
        let first = RuntimeBuilder::current_thread()
            .build()
            .expect("build runtime");
        let second = first.clone();

        assert!(
            !first.shutdown_timeout(Duration::ZERO),
            "the first call cannot finish while the second Runtime remains"
        );
        assert!(
            second.shutdown_timeout(Duration::from_secs(10)),
            "the second caller must release its Arc and observe the first reaper's completion"
        );
    }

    #[test]
    fn shutdown_waits_for_inflight_spawn_publication_before_stopping_scheduler() {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(1, 1)
            .build()
            .expect("build runtime");
        let retained = runtime.clone();
        let shutdown_complete = Arc::clone(&runtime.inner.shutdown_completion);
        let retained_blocking_handle = runtime
            .blocking_handle()
            .expect("configured runtime exposes its blocking pool");
        let publisher = runtime
            .inner
            .spawn_liveness_guard()
            .expect("runtime accepts spawn publication");

        assert!(!runtime.shutdown_timeout(Duration::ZERO));
        assert!(
            !retained.inner.scheduler.is_shutdown(),
            "the scheduler must remain live until the admitted publication finishes"
        );
        assert!(
            retained
                .inner
                .blocking_pool
                .as_ref()
                .expect("configured blocking pool")
                .is_shutdown(),
            "blocking-pool admission must close even while scheduler publication is in flight"
        );
        let rejected = retained_blocking_handle.spawn(|| {
            panic!("retained blocking handle must not admit work during shutdown");
        });
        assert!(rejected.is_cancelled());
        assert!(rejected.wait_timeout(Duration::from_secs(1)));

        drop(publisher);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !retained.inner.scheduler.is_shutdown() {
            assert!(
                Instant::now() < deadline,
                "the reaper must signal shutdown after publication finishes"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            retained
                .inner
                .blocking_pool
                .as_ref()
                .expect("configured blocking pool")
                .is_shutdown(),
            "blocking-pool admission must remain closed after publication completes"
        );
        drop(retained);
        assert!(shutdown_complete.wait_timeout(Duration::from_secs(10)));
    }

    #[test]
    fn shutdown_timeout_closes_all_runtime_owned_spawn_surfaces() {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(1, 1)
            .build()
            .expect("build runtime");
        let retained_runtime = runtime.clone();
        let retained_handle = runtime.handle();
        let retained_cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let retained_blocking_handle = runtime
            .blocking_handle()
            .expect("configured runtime exposes its blocking pool");
        let shutdown_complete = Arc::clone(&runtime.inner.shutdown_completion);

        assert!(runtime.blocking_handle().is_some());
        assert!(
            !runtime.shutdown_timeout(Duration::ZERO),
            "strong runtime owners keep final teardown incomplete"
        );

        assert!(matches!(
            retained_handle.try_spawn(async {}),
            Err(SpawnError::RuntimeUnavailable)
        ));
        assert!(matches!(
            retained_handle.try_spawn_with_cx(|_| async {}),
            Err(SpawnError::RuntimeUnavailable)
        ));
        assert!(matches!(
            retained_cx.spawn(|_| async { 1_u8 }),
            Err(SpawnError::RuntimeUnavailable)
        ));
        assert!(matches!(
            retained_cx.spawn_blocking(|_| 1_u8),
            Err(SpawnError::RuntimeUnavailable)
        ));
        assert!(matches!(
            retained_cx.spawn_local(|_| async { 1_u8 }),
            Err(SpawnError::RuntimeUnavailable)
        ));
        assert!(retained_runtime.spawn_blocking(|| {}).is_none());
        assert!(retained_handle.spawn_blocking(|| {}).is_none());
        assert!(retained_runtime.blocking_handle().is_none());
        assert!(retained_handle.blocking_handle().is_none());
        let rejected_blocking_task = retained_blocking_handle.spawn(|| {
            panic!("a retained blocking handle must not run after shutdown starts");
        });
        assert!(rejected_blocking_task.is_cancelled());
        assert!(rejected_blocking_task.wait_timeout(Duration::from_secs(1)));

        drop(retained_cx);
        drop(retained_blocking_handle);
        drop(retained_handle);
        drop(retained_runtime);
        assert!(shutdown_complete.wait_timeout(Duration::from_secs(10)));
    }

    #[derive(Default)]
    struct RecordingNativeHostServices {
        worker_bootstrap_calls: AtomicUsize,
        deadline_monitor_calls: AtomicUsize,
    }

    impl RuntimeHostServices for RecordingNativeHostServices {
        fn kind(&self) -> RuntimeHostServicesKind {
            RuntimeHostServicesKind::NativeStdThread
        }

        fn spawn_workers(
            &self,
            runtime: &Arc<RuntimeInner>,
            workers: Vec<ThreeLaneWorker>,
        ) -> io::Result<Vec<std::thread::JoinHandle<()>>> {
            self.worker_bootstrap_calls.fetch_add(1, Ordering::Relaxed);
            NativeThreadHostServices::spawn_worker_threads(runtime, workers)
        }

        fn start_deadline_monitor(
            &self,
            config: &RuntimeConfig,
            state: &Arc<crate::sync::ContendedMutex<RuntimeState>>,
            dispatch_task_table: Option<
                Arc<crate::sync::ContendedMutex<crate::runtime::TaskTable>>,
            >,
        ) -> DeadlineMonitorHostService {
            self.deadline_monitor_calls.fetch_add(1, Ordering::Relaxed);
            NativeThreadHostServices::start_deadline_monitor(config, state, dispatch_task_table)
        }
    }

    struct CoordinatedDeadlineMonitorHostServices {
        started: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>,
        rescue_shutdown: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>,
    }

    impl CoordinatedDeadlineMonitorHostServices {
        fn new() -> (Self, std::sync::mpsc::Receiver<()>) {
            let (started, started_rx) = std::sync::mpsc::channel();
            (
                Self {
                    started: std::sync::Mutex::new(Some(started)),
                    rescue_shutdown: std::sync::Mutex::new(None),
                },
                started_rx,
            )
        }

        fn rescue_shutdown(&self) {
            if let Some(shutdown) = self
                .rescue_shutdown
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                let _ = shutdown.send(());
            }
        }
    }

    impl RuntimeHostServices for CoordinatedDeadlineMonitorHostServices {
        fn kind(&self) -> RuntimeHostServicesKind {
            RuntimeHostServicesKind::NativeStdThread
        }

        fn spawn_workers(
            &self,
            _runtime: &Arc<RuntimeInner>,
            _workers: Vec<ThreeLaneWorker>,
        ) -> io::Result<Vec<std::thread::JoinHandle<()>>> {
            Ok(Vec::new())
        }

        fn start_deadline_monitor(
            &self,
            config: &RuntimeConfig,
            _state: &Arc<crate::sync::ContendedMutex<RuntimeState>>,
            _dispatch_task_table: Option<
                Arc<crate::sync::ContendedMutex<crate::runtime::TaskTable>>,
            >,
        ) -> DeadlineMonitorHostService {
            let monitor_config = match config.deadline_monitor {
                Some(ref monitor) if monitor.enabled => monitor,
                _ => return DeadlineMonitorHostService::disabled(),
            };

            let (shutdown, shutdown_rx) = std::sync::mpsc::channel();
            *self
                .rescue_shutdown
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(shutdown.clone());
            let started = self
                .started
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .expect("coordinated monitor should start exactly once");
            let check_interval = monitor_config.check_interval;
            let thread = std::thread::Builder::new()
                .name("coordinated-deadline-monitor".to_string())
                .spawn(move || {
                    let _ = started.send(());
                    let _ = wait_for_deadline_monitor_tick(&shutdown_rx, check_interval);
                })
                .expect("coordinated deadline monitor thread should start");

            DeadlineMonitorHostService {
                shutdown: Some(shutdown),
                thread: Some(thread),
            }
        }
    }

    #[test]
    fn browser_host_services_contract_pins_threadless_startup_requirements() {
        let contract = BrowserHostServicesContract::V1;
        assert!(
            contract
                .required_capabilities
                .contains(&"host-turn wakeups"),
            "browser contract must require host-turn wakeups"
        );
        assert!(
            contract
                .required_capabilities
                .contains(&"worker bootstrap hooks"),
            "browser contract must require worker bootstrap hooks"
        );
        assert!(
            contract
                .required_capabilities
                .contains(&"timer/deadline driving"),
            "browser contract must require timer/deadline driving"
        );
        assert!(
            contract
                .required_capabilities
                .contains(&"lane-health callbacks"),
            "browser contract must require lane-health callbacks"
        );
        assert!(
            contract
                .diagnostic_requirements()
                .contains("threadless startup"),
            "diagnostics should explain why the browser path is threadless"
        );
    }

    #[test]
    fn browser_bootstrap_error_describes_host_services_requirements() {
        let message = unsupported_browser_bootstrap_message(&NativeThreadHostServices::new());
        assert!(
            message.contains("RuntimeHostServices seam"),
            "diagnostic should name the startup seam: {message}"
        );
        assert!(
            message.contains("native-std-thread"),
            "diagnostic should name the shipped native host implementation: {message}"
        );
        assert!(
            message.contains("host-turn wakeups") && message.contains("lane-health callbacks"),
            "diagnostic should enumerate the missing browser host requirements: {message}"
        );
        assert!(
            message.contains("threadless startup"),
            "diagnostic should explain the threadless browser target: {message}"
        );
    }

    fn browser_probe(
        host_role: BrowserExecutionHostRole,
        runtime_context: BrowserRuntimeContext,
        has_window: bool,
        has_document: bool,
        has_webassembly: bool,
    ) -> BrowserExecutionProbe {
        BrowserExecutionProbe {
            has_global_this: true,
            runtime_context,
            host_role,
            capabilities: BrowserCapabilitySnapshot {
                execution_api: BrowserExecutionApiCapabilities {
                    has_abort_controller: true,
                    has_fetch: true,
                    has_webassembly,
                },
                dom: BrowserDomCapabilities {
                    has_document,
                    has_window,
                },
                storage: browser_storage_capabilities_for_host_role(host_role),
                transport: BrowserTransportCapabilities {
                    has_web_socket: true,
                    has_web_transport: false,
                },
            },
        }
    }

    #[test]
    fn browser_execution_ladder_selects_main_thread_lane_for_supported_probe() {
        let diagnostics = build_browser_execution_ladder_from_probe(
            None,
            browser_probe(
                BrowserExecutionHostRole::BrowserMainThread,
                BrowserRuntimeContext::BrowserMainThread,
                true,
                true,
                true,
            ),
        );

        assert!(
            diagnostics.supported,
            "main-thread probe should be supported"
        );
        assert_eq!(
            diagnostics.selected_lane,
            BrowserExecutionLane::BrowserMainThreadDirectRuntime,
            "main-thread probe should select the main-thread direct-runtime lane"
        );
        assert_eq!(
            diagnostics.reason_code,
            BrowserExecutionReasonCode::Supported,
            "supported probe should keep the supported reason code"
        );
        assert_eq!(
            diagnostics.host_role,
            BrowserExecutionHostRole::BrowserMainThread,
            "host role should stay on the browser main thread"
        );
        assert_eq!(
            diagnostics.runtime_context,
            BrowserRuntimeContext::BrowserMainThread,
            "runtime context should stay on the browser main thread"
        );
        let selected_candidate = diagnostics
            .candidates
            .iter()
            .find(|candidate| candidate.selected)
            .expect("one selected candidate");
        assert_eq!(
            selected_candidate.lane_id,
            BrowserExecutionLane::BrowserMainThreadDirectRuntime,
            "selected candidate should match the selected lane"
        );
        assert!(
            diagnostics.capabilities.storage.has_indexed_db,
            "main-thread probe should surface IndexedDB availability in ladder diagnostics"
        );
        assert!(
            diagnostics.capabilities.storage.has_local_storage,
            "main-thread probe should surface localStorage availability in ladder diagnostics"
        );
    }

    #[test]
    fn browser_execution_ladder_preserves_truthful_lane_when_preferred_lane_mismatches() {
        let diagnostics = build_browser_execution_ladder_from_probe(
            Some(BrowserExecutionLane::DedicatedWorkerDirectRuntime),
            browser_probe(
                BrowserExecutionHostRole::BrowserMainThread,
                BrowserRuntimeContext::BrowserMainThread,
                true,
                true,
                true,
            ),
        );

        assert_eq!(
            diagnostics.selected_lane,
            BrowserExecutionLane::BrowserMainThreadDirectRuntime,
            "preferred-lane mismatch must not override the truthful selected lane"
        );
        assert_eq!(
            diagnostics.reason_code,
            BrowserExecutionReasonCode::Supported,
            "preferred-lane mismatch should not rewrite the truthful selected reason"
        );
        assert!(
            diagnostics
                .message
                .contains("lane.browser.dedicated_worker.direct_runtime"),
            "message should name the preferred lane mismatch"
        );
        assert!(
            diagnostics
                .guidance
                .iter()
                .any(|entry| entry.contains("switch entrypoints")),
            "guidance should explain how to satisfy the preferred lane"
        );
    }

    #[test]
    fn browser_execution_ladder_keeps_prerequisite_reason_when_preferred_lane_fails_closed() {
        let diagnostics = build_browser_execution_ladder_from_probe(
            Some(BrowserExecutionLane::BrowserMainThreadDirectRuntime),
            browser_probe(
                BrowserExecutionHostRole::BrowserMainThread,
                BrowserRuntimeContext::BrowserMainThread,
                true,
                true,
                false,
            ),
        );

        assert_eq!(
            diagnostics.selected_lane,
            BrowserExecutionLane::Unsupported,
            "missing prerequisites should still fail closed to lane.unsupported"
        );
        assert_eq!(
            diagnostics.reason_code,
            BrowserExecutionReasonCode::MissingWebAssembly,
            "preferred-lane mismatch must preserve the real missing-prerequisite reason"
        );
        assert!(
            diagnostics.message.contains("missing_webassembly"),
            "message should preserve the real missing-prerequisite reason code"
        );
        assert!(
            diagnostics
                .guidance
                .iter()
                .any(|entry| entry.contains("Restore the reported Browser Edition prerequisites")),
            "guidance should explain how to restore the missing prerequisite"
        );
    }

    #[test]
    fn browser_execution_ladder_distinguishes_intentional_fail_closed_preference() {
        let diagnostics = build_browser_execution_ladder_from_probe(
            Some(BrowserExecutionLane::Unsupported),
            browser_probe(
                BrowserExecutionHostRole::BrowserMainThread,
                BrowserRuntimeContext::BrowserMainThread,
                true,
                true,
                true,
            ),
        );

        assert_eq!(
            diagnostics.selected_lane,
            BrowserExecutionLane::BrowserMainThreadDirectRuntime,
            "preferred fallback pin must not override the truthful direct-runtime lane"
        );
        assert_eq!(
            diagnostics.reason_code,
            BrowserExecutionReasonCode::Supported,
            "preferred fallback pin should not rewrite the selected reason"
        );
        assert!(
            diagnostics
                .message
                .contains("lower-priority fail-closed fallback"),
            "message should describe the explicit fallback pin instead of a host-role mismatch"
        );
        assert!(
            diagnostics
                .guidance
                .iter()
                .any(|entry| entry.contains("Only pin")),
            "guidance should explain that lane.unsupported is an intentional fail-closed pin"
        );
    }

    #[test]
    fn browser_execution_ladder_fail_closes_non_browser_probe() {
        let diagnostics =
            build_browser_execution_ladder_from_probe(None, BrowserExecutionProbe::non_browser());

        assert!(!diagnostics.supported, "non-browser probe must fail closed");
        assert_eq!(
            diagnostics.selected_lane,
            BrowserExecutionLane::Unsupported,
            "non-browser probe must demote to the terminal unsupported lane"
        );
        assert_eq!(
            diagnostics.reason_code,
            BrowserExecutionReasonCode::MissingGlobalThis,
            "non-browser probe should surface the missing-global diagnostic"
        );
    }

    #[test]
    fn browser_execution_ladder_fail_closes_service_worker_probe_with_not_shipped_reason() {
        let diagnostics = RuntimeBuilder::new()
            .inspect_browser_execution_ladder_for_probe(BrowserExecutionProbe::service_worker());

        assert!(!diagnostics.supported, "service worker must fail close");
        assert_eq!(
            diagnostics.selected_lane,
            BrowserExecutionLane::Unsupported,
            "service worker must remain on the fail-closed lane"
        );
        assert_eq!(
            diagnostics.host_role,
            BrowserExecutionHostRole::ServiceWorker,
            "service worker probe must preserve host role"
        );
        assert_eq!(
            diagnostics.runtime_context,
            BrowserRuntimeContext::ServiceWorker,
            "service worker probe must preserve the explicit service-worker runtime context"
        );
        assert_eq!(
            diagnostics.reason_code,
            BrowserExecutionReasonCode::ServiceWorkerDirectRuntimeNotShipped,
            "service worker probe must preserve the explicit not-shipped reason"
        );
        assert_eq!(
            diagnostics.runtime_support.reason,
            BrowserRuntimeSupportReason::ServiceWorkerNotYetShipped,
            "runtime-support reason must stay aligned with the execution-ladder reason"
        );
        assert_eq!(
            diagnostics.runtime_support.runtime_context,
            BrowserRuntimeContext::ServiceWorker,
            "runtime-support diagnostics must preserve the explicit service-worker runtime context"
        );
        assert!(
            diagnostics.capabilities.storage.has_indexed_db,
            "service-worker probe should surface truthful IndexedDB support even while direct runtime stays fail-closed"
        );
        assert!(
            !diagnostics.capabilities.storage.has_local_storage,
            "service-worker probe should keep localStorage unavailable"
        );
        assert!(
            diagnostics
                .guidance
                .iter()
                .any(|entry| entry.contains("service-worker broker")),
            "service-worker guidance should point callers at the bounded broker helpers"
        );
    }

    #[test]
    fn browser_service_worker_broker_support_is_explicit_for_service_worker_probe() {
        let diagnostics = RuntimeBuilder::new()
            .inspect_browser_service_worker_broker_support_for_probe(
                BrowserExecutionProbe::service_worker(),
            );

        assert!(
            diagnostics.supported,
            "service-worker broker support must be explicit for a truthful service-worker probe"
        );
        assert_eq!(
            diagnostics.contract_id, BROWSER_SERVICE_WORKER_BROKER_CONTRACT_ID,
            "service-worker broker contract id must stay stable"
        );
        assert_eq!(
            diagnostics.requested_lane, BROWSER_SERVICE_WORKER_BROKER_LANE,
            "service-worker broker lane id must stay stable"
        );
        assert_eq!(
            diagnostics.fallback_target,
            BrowserWorkerFallbackTarget::DedicatedWorkerDirectRuntime,
            "service-worker broker should prefer the dedicated-worker fallback first"
        );
        assert_eq!(
            diagnostics.fallback_lane_id,
            Some(BrowserExecutionLane::DedicatedWorkerDirectRuntime),
            "service-worker broker should map its first fallback to the dedicated-worker lane"
        );
        assert_eq!(
            diagnostics.reason,
            BrowserServiceWorkerBrokerSupportReason::Supported,
            "service-worker broker reason must remain supported on the truthful host"
        );
        assert_eq!(
            diagnostics.direct_runtime_reason,
            BrowserRuntimeSupportReason::ServiceWorkerNotYetShipped,
            "service-worker broker must preserve the fail-closed direct-runtime truth"
        );
        assert_eq!(
            diagnostics.direct_execution_reason_code,
            BrowserExecutionReasonCode::ServiceWorkerDirectRuntimeNotShipped,
            "service-worker broker must preserve the fail-closed direct execution reason"
        );
        assert!(
            diagnostics
                .guidance
                .iter()
                .any(|entry| entry.contains("registration-scope")),
            "service-worker broker guidance should preserve explicit broker-admission boundaries"
        );
    }

    #[test]
    fn browser_execution_ladder_fail_closes_shared_worker_probe_with_not_shipped_reason() {
        let diagnostics = RuntimeBuilder::new()
            .inspect_browser_execution_ladder_for_probe(BrowserExecutionProbe::shared_worker());

        assert!(!diagnostics.supported, "shared worker must fail close");
        assert_eq!(
            diagnostics.selected_lane,
            BrowserExecutionLane::Unsupported,
            "shared worker must remain on the fail-closed lane"
        );
        assert_eq!(
            diagnostics.host_role,
            BrowserExecutionHostRole::SharedWorker,
            "shared worker probe must preserve host role"
        );
        assert_eq!(
            diagnostics.runtime_context,
            BrowserRuntimeContext::SharedWorker,
            "shared worker probe must preserve the explicit shared-worker runtime context"
        );
        assert_eq!(
            diagnostics.reason_code,
            BrowserExecutionReasonCode::SharedWorkerDirectRuntimeNotShipped,
            "shared worker probe must preserve the explicit not-shipped reason"
        );
        assert_eq!(
            diagnostics.runtime_support.reason,
            BrowserRuntimeSupportReason::SharedWorkerNotYetShipped,
            "runtime-support reason must stay aligned with the execution-ladder reason"
        );
        assert_eq!(
            diagnostics.runtime_support.runtime_context,
            BrowserRuntimeContext::SharedWorker,
            "runtime-support diagnostics must preserve the explicit shared-worker runtime context"
        );
        assert!(
            diagnostics.capabilities.storage.has_indexed_db,
            "shared-worker probe should surface truthful IndexedDB support even while direct runtime stays fail-closed"
        );
        assert!(
            !diagnostics.capabilities.storage.has_local_storage,
            "shared-worker probe should keep localStorage unavailable"
        );
        assert!(
            diagnostics
                .guidance
                .iter()
                .any(|entry| entry.contains("shared-worker coordinator")),
            "shared-worker guidance should point callers at the bounded coordinator helpers"
        );
        assert!(
            diagnostics
                .guidance
                .iter()
                .any(|entry| entry.contains("browser main-thread or dedicated-worker")),
            "shared-worker guidance should preserve the truthful caller boundary"
        );
    }

    #[test]
    fn browser_shared_worker_coordinator_support_is_explicit_for_supported_callers() {
        let main_thread = RuntimeBuilder::new()
            .inspect_browser_shared_worker_coordinator_support_for_probe(
                BrowserExecutionProbe::browser_main_thread(),
            );
        let dedicated_worker = RuntimeBuilder::new()
            .inspect_browser_shared_worker_coordinator_support_for_probe(
                BrowserExecutionProbe::dedicated_worker(),
            );

        assert!(
            main_thread.supported,
            "browser main thread must remain a truthful shared-worker coordinator caller"
        );
        assert_eq!(
            main_thread.contract_id, BROWSER_SHARED_WORKER_COORDINATOR_CONTRACT_ID,
            "shared-worker coordinator contract id must stay stable"
        );
        assert_eq!(
            main_thread.requested_lane, BROWSER_SHARED_WORKER_COORDINATOR_LANE,
            "shared-worker coordinator lane id must stay stable"
        );
        assert_eq!(
            main_thread.fallback_target,
            BrowserWorkerFallbackTarget::BrowserMainThreadDirectRuntime,
            "browser main-thread callers should preserve their current lane as the first truthful fallback"
        );
        assert_eq!(
            main_thread.fallback_lane_id,
            Some(BrowserExecutionLane::BrowserMainThreadDirectRuntime),
            "browser main-thread callers should map the first fallback to the current direct-runtime lane"
        );
        assert_eq!(
            main_thread.reason,
            BrowserSharedWorkerCoordinatorSupportReason::Supported,
            "browser main-thread callers must preserve the bounded coordinator support reason"
        );
        assert_eq!(
            main_thread.direct_runtime_reason,
            BrowserRuntimeSupportReason::SharedWorkerNotYetShipped,
            "caller-side coordinator diagnostics must preserve the shared-worker fail-closed truth"
        );
        assert_eq!(
            main_thread.direct_execution_reason_code,
            BrowserExecutionReasonCode::SharedWorkerDirectRuntimeNotShipped,
            "caller-side coordinator diagnostics must preserve the shared-worker execution reason"
        );
        assert!(
            main_thread
                .guidance
                .iter()
                .any(|entry| entry.contains("same-origin")),
            "shared-worker coordinator guidance should preserve explicit JS attach prerequisites"
        );

        assert!(
            dedicated_worker.supported,
            "dedicated-worker callers must remain truthful shared-worker coordinator callers"
        );
        assert_eq!(
            dedicated_worker.fallback_target,
            BrowserWorkerFallbackTarget::DedicatedWorkerDirectRuntime,
            "dedicated-worker callers should preserve their current lane as the first truthful fallback"
        );
        assert_eq!(
            dedicated_worker.fallback_lane_id,
            Some(BrowserExecutionLane::DedicatedWorkerDirectRuntime),
            "dedicated-worker callers should map the first fallback to the current direct-runtime lane"
        );
    }

    #[test]
    fn browser_shared_worker_coordinator_support_rejects_shared_worker_host() {
        let diagnostics = RuntimeBuilder::new()
            .inspect_browser_shared_worker_coordinator_support_for_probe(
                BrowserExecutionProbe::shared_worker(),
            );

        assert!(
            !diagnostics.supported,
            "shared-worker coordinator preflight must reject the shared-worker host itself"
        );
        assert_eq!(
            diagnostics.reason,
            BrowserSharedWorkerCoordinatorSupportReason::SharedWorkerApiMissing,
            "shared-worker coordinator preflight must preserve the unsupported-caller reason"
        );
        assert!(
            diagnostics
                .guidance
                .iter()
                .any(|entry| entry.contains("browser main-thread or dedicated-worker")),
            "shared-worker coordinator rejection guidance must preserve the truthful caller boundary"
        );
    }

    #[test]
    fn browser_execution_ladder_preserves_truthful_worker_storage_snapshots() {
        let dedicated = RuntimeBuilder::new()
            .inspect_browser_execution_ladder_for_probe(BrowserExecutionProbe::dedicated_worker());

        assert!(
            dedicated.capabilities.storage.has_indexed_db,
            "dedicated-worker probe should surface IndexedDB availability"
        );
        assert!(
            !dedicated.capabilities.storage.has_local_storage,
            "dedicated-worker probe should keep localStorage unavailable"
        );
    }

    #[test]
    fn browser_execution_ladder_keeps_missing_webassembly_visible_in_candidates() {
        let diagnostics = build_browser_execution_ladder_from_probe(
            None,
            browser_probe(
                BrowserExecutionHostRole::BrowserMainThread,
                BrowserRuntimeContext::BrowserMainThread,
                true,
                true,
                false,
            ),
        );

        assert_eq!(
            diagnostics.selected_lane,
            BrowserExecutionLane::Unsupported,
            "missing WebAssembly must fail closed to the unsupported lane"
        );
        assert_eq!(
            diagnostics.reason_code,
            BrowserExecutionReasonCode::MissingWebAssembly,
            "selected reason should preserve the real missing-prerequisite failure"
        );
        let direct_candidate = diagnostics
            .candidates
            .iter()
            .find(|candidate| {
                candidate.lane_id == BrowserExecutionLane::BrowserMainThreadDirectRuntime
            })
            .expect("main-thread candidate");
        assert_eq!(
            direct_candidate.reason_code,
            BrowserExecutionReasonCode::CandidatePrerequisiteMissing,
            "direct lane candidate should remain a prerequisite-missing rejection"
        );
    }

    #[test]
    fn browser_runtime_builder_selection_constructs_runtime_for_supported_probe() {
        let selection = build_browser_runtime_selection_from_probe(
            None,
            None,
            WasmAbortPropagationMode::Bidirectional,
            browser_probe(
                BrowserExecutionHostRole::BrowserMainThread,
                BrowserRuntimeContext::BrowserMainThread,
                true,
                true,
                true,
            ),
        );

        assert!(
            selection.runtime_available(),
            "supported probe should construct a preview browser runtime"
        );
        assert_eq!(
            selection.execution_ladder.selected_lane,
            BrowserExecutionLane::BrowserMainThreadDirectRuntime,
            "supported probe should stay on the truthful main-thread lane"
        );
        let runtime = selection.runtime.expect("supported runtime");
        let scope = runtime
            .enter_scope(Some("browser-runtime-selection-smoke"))
            .expect("scope should open");
        let scope_close = runtime
            .close_scope(&scope)
            .expect("scope close should succeed");
        assert!(
            matches!(scope_close, WasmAbiOutcomeEnvelope::Ok { .. }),
            "scope close should return an ok outcome"
        );
        let runtime_close = runtime.close().expect("runtime close should succeed");
        assert!(
            matches!(runtime_close, WasmAbiOutcomeEnvelope::Ok { .. }),
            "runtime close should return an ok outcome"
        );
        assert!(
            runtime.dispatcher_diagnostics().is_clean(),
            "dispatcher should be clean after full runtime teardown"
        );
    }

    #[test]
    fn browser_runtime_builder_consumer_version_negotiates_abi_contract() {
        let supported_probe = browser_probe(
            BrowserExecutionHostRole::BrowserMainThread,
            BrowserRuntimeContext::BrowserMainThread,
            true,
            true,
            true,
        );

        for consumer_version in [
            WasmAbiVersion::CURRENT,
            WasmAbiVersion {
                major: WasmAbiVersion::CURRENT.major,
                minor: WasmAbiVersion::CURRENT.minor + 1,
            },
        ] {
            let selection = build_browser_runtime_selection_from_probe(
                None,
                Some(consumer_version),
                WasmAbortPropagationMode::Bidirectional,
                supported_probe,
            );
            assert!(
                selection.runtime_available(),
                "compatible consumer ABI {consumer_version} should construct the preview runtime"
            );
            assert!(selection.error.is_none(), "compatible ABI must not error");
            let runtime = selection.runtime.expect("compatible runtime");
            assert_eq!(
                runtime.consumer_version(),
                Some(consumer_version),
                "runtime must retain the consumer ABI version used at the boundary"
            );
            runtime.close().expect("compatible runtime closes cleanly");
        }

        let newer_producer = WasmAbiVersion {
            major: WasmAbiVersion::CURRENT.major,
            minor: WasmAbiVersion::CURRENT.minor + 1,
        };
        let old_consumer = WasmAbiVersion::CURRENT;
        let selection = build_browser_runtime_selection_with_dispatcher_from_probe(
            None,
            Some(old_consumer),
            WasmAbortPropagationMode::Bidirectional,
            supported_probe,
            WasmExportDispatcher::new().with_producer_version_for_test(newer_producer),
        );

        assert!(
            !selection.runtime_available(),
            "consumer ABI older than producer minor must fail closed"
        );
        assert_eq!(
            selection.execution_ladder.selected_lane,
            BrowserExecutionLane::BrowserMainThreadDirectRuntime,
            "consumer-too-old mismatch must preserve truthful host lane diagnostics"
        );
        let error = selection.error.expect("structured consumer-too-old error");
        match error {
            BrowserRuntimeBuildError::RuntimeCreate {
                source:
                    WasmDispatchError::Incompatible {
                        decision:
                            crate::types::WasmAbiCompatibilityDecision::ConsumerTooOld {
                                producer_minor,
                                consumer_minor,
                            },
                    },
                ..
            } => {
                assert_eq!(producer_minor, newer_producer.minor);
                assert_eq!(consumer_minor, old_consumer.minor);
            }
            other => panic!("expected ABI consumer-too-old runtime-create error, got {other:?}"),
        }

        let incompatible = WasmAbiVersion {
            major: WasmAbiVersion::CURRENT.major + 1,
            minor: 0,
        };
        let selection = build_browser_runtime_selection_from_probe(
            None,
            Some(incompatible),
            WasmAbortPropagationMode::Bidirectional,
            supported_probe,
        );

        assert!(
            !selection.runtime_available(),
            "major-mismatched consumer ABI must fail closed"
        );
        assert_eq!(
            selection.execution_ladder.selected_lane,
            BrowserExecutionLane::BrowserMainThreadDirectRuntime,
            "ABI mismatch must preserve the truthful host lane diagnostics"
        );
        let error = selection.error.expect("structured ABI mismatch error");
        match error {
            BrowserRuntimeBuildError::RuntimeCreate {
                source:
                    WasmDispatchError::Incompatible {
                        decision:
                            crate::types::WasmAbiCompatibilityDecision::MajorMismatch {
                                producer_major,
                                consumer_major,
                            },
                    },
                ..
            } => {
                assert_eq!(producer_major, WasmAbiVersion::CURRENT.major);
                assert_eq!(consumer_major, incompatible.major);
            }
            other => panic!("expected ABI major mismatch runtime-create error, got {other:?}"),
        }
    }

    #[test]
    fn browser_runtime_builder_selection_preserves_truthful_lane_under_mismatch() {
        let selection = build_browser_runtime_selection_from_probe(
            Some(BrowserExecutionLane::DedicatedWorkerDirectRuntime),
            None,
            WasmAbortPropagationMode::Bidirectional,
            browser_probe(
                BrowserExecutionHostRole::BrowserMainThread,
                BrowserRuntimeContext::BrowserMainThread,
                true,
                true,
                true,
            ),
        );

        assert!(
            selection.runtime_available(),
            "preferred-lane mismatch should still construct a runtime when a truthful lane exists"
        );
        assert_eq!(
            selection.execution_ladder.selected_lane,
            BrowserExecutionLane::BrowserMainThreadDirectRuntime,
            "preferred-lane mismatch must preserve the truthful selected lane"
        );
        assert_eq!(
            selection.execution_ladder.preferred_lane,
            Some(BrowserExecutionLane::DedicatedWorkerDirectRuntime),
            "selection should retain the requested preferred lane for diagnostics"
        );
    }

    #[test]
    fn browser_runtime_builder_selection_fail_closes_when_webassembly_missing() {
        let selection = build_browser_runtime_selection_from_probe(
            None,
            None,
            WasmAbortPropagationMode::Bidirectional,
            browser_probe(
                BrowserExecutionHostRole::BrowserMainThread,
                BrowserRuntimeContext::BrowserMainThread,
                true,
                true,
                false,
            ),
        );

        assert!(
            !selection.runtime_available(),
            "missing WebAssembly must fail close instead of constructing a runtime"
        );
        let error = selection.error.expect("structured unsupported error");
        assert!(matches!(
            error,
            BrowserRuntimeBuildError::Unsupported { .. }
        ));
        assert_eq!(
            error.execution_ladder().reason_code,
            BrowserExecutionReasonCode::MissingWebAssembly,
            "structured unsupported error must preserve the real missing-prerequisite reason"
        );
    }

    #[test]
    fn browser_runtime_builder_build_returns_structured_unsupported_error() {
        let error = BrowserRuntimeBuilder::new().build().expect_err(
            "native test host should fail-close instead of constructing a browser runtime",
        );

        assert!(matches!(
            error,
            BrowserRuntimeBuildError::Unsupported { .. }
        ));
        assert_eq!(
            error.execution_ladder().selected_lane,
            BrowserExecutionLane::Unsupported,
            "native host should fail-close to lane.unsupported"
        );
    }

    #[test]
    fn runtime_builder_routes_native_startup_through_host_services_seam() {
        init_test_logging();

        let host_services = Arc::new(RecordingNativeHostServices::default());
        let seam: Arc<dyn RuntimeHostServices> = host_services.clone();
        let mut builder = RuntimeBuilder::current_thread();
        builder.host_services = seam;

        let runtime = builder.build().expect("runtime build");
        let result = runtime.block_on(runtime.handle().spawn(async { 7u32 }));

        assert_eq!(result, 7, "runtime should remain usable through the seam");
        assert_eq!(
            host_services.worker_bootstrap_calls.load(Ordering::SeqCst),
            1,
            "worker startup should route through the host-services seam"
        );
        assert_eq!(
            host_services.deadline_monitor_calls.load(Ordering::SeqCst),
            1,
            "deadline-monitor startup should route through the host-services seam"
        );
    }

    #[test]
    fn runtime_builder_normalizes_zero_deadline_monitor_interval() {
        init_test_logging();

        let runtime = RuntimeBuilder::current_thread()
            .deadline_monitoring(|monitor| monitor.enabled(true).check_interval(Duration::ZERO))
            .build()
            .expect("runtime builder should normalize a zero monitor interval");

        let monitor = runtime
            .inner
            .config
            .deadline_monitor
            .as_ref()
            .expect("deadline monitoring should remain enabled");
        assert_eq!(
            monitor.check_interval,
            MonitorConfig::default().check_interval,
            "builder configuration should normalize zero to the safe default interval"
        );
    }

    #[test]
    fn runtime_with_config_normalizes_zero_deadline_monitor_interval() {
        init_test_logging();

        let mut config = RuntimeConfig::default();
        config.worker_threads = 1;
        config.deadline_monitor = Some(MonitorConfig {
            check_interval: Duration::ZERO,
            enabled: true,
            ..MonitorConfig::default()
        });

        let runtime = Runtime::with_config(config)
            .expect("direct runtime configuration should normalize a zero monitor interval");
        let monitor = runtime
            .inner
            .config
            .deadline_monitor
            .as_ref()
            .expect("deadline monitoring should remain enabled");
        assert_eq!(
            monitor.check_interval,
            MonitorConfig::default().check_interval,
            "direct configuration should normalize zero at the common constructor"
        );
    }

    /// E1.2 subsystem 3d (br-asupersync-sched-hot-path-perf-bt4y5f.2.2):
    /// end-to-end smoke for the internal Sharded construction. Default
    /// admission is `Direct`, so `RuntimeHandle::spawn` exercises the B09
    /// legacy fallback — the task must mint into shard A (a task minted
    /// into the embedded table would never dispatch, and the channel recv
    /// below would time out). Liveness (B12/B02) must read the dispatch
    /// table, proven by quiescence parity with a unified twin runtime.
    #[test]
    fn sharded_shape_runtime_spawns_via_fallback_and_quiesces() {
        init_test_logging();

        let build = |shape: crate::runtime::config::RuntimeStateShape| {
            let mut config = RuntimeConfig::default();
            config.worker_threads = 2;
            config.runtime_state_shape = shape;
            Runtime::with_config_and_platform(
                config,
                None,
                None,
                None,
                None,
                &NativeThreadHostServices::new(),
            )
            .expect("runtime constructs")
        };
        let run_one_task = |runtime: &Runtime| {
            let (tx, rx) = std::sync::mpsc::channel();
            let handle = runtime.handle();
            let join = handle.spawn(async move {
                tx.send(42_u32).expect("send from sharded worker");
            });
            let value = rx
                .recv_timeout(Duration::from_secs(10))
                .expect("spawned task must dispatch (a wrong-table mint never runs)");
            assert_eq!(value, 42);
            drop(join);
        };

        let sharded = build(crate::runtime::config::RuntimeStateShape::Sharded);
        let table = sharded
            .inner
            .scheduler
            .dispatch_task_table()
            .expect("sharded runtime dispatches against a task table");
        let shards = sharded
            .inner
            .sharded_state
            .as_ref()
            .expect("sharded runtime retains its ShardedState");
        assert!(
            Arc::ptr_eq(&table, &shards.tasks),
            "the dispatch table must be ShardedState's shard A itself"
        );

        run_one_task(&sharded);

        let unified = build(crate::runtime::config::RuntimeStateShape::Unified);
        assert!(
            unified.inner.scheduler.dispatch_task_table().is_none(),
            "unified twin keeps the embedded table"
        );
        run_one_task(&unified);

        // Live-task phase: hold one task blocked on each shape and require
        // quiescence parity — B02 must see the live shard-A task exactly as
        // the unified shape sees its embedded one.
        let hold_one_task = |runtime: &Runtime| {
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let (running_tx, running_rx) = std::sync::mpsc::channel::<()>();
            let handle = runtime.handle();
            let join = handle.spawn(async move {
                running_tx.send(()).expect("signal running");
                release_rx
                    .recv_timeout(Duration::from_secs(10))
                    .expect("release signal");
            });
            running_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("blocked task reaches running");
            (release_tx, join)
        };
        let (sharded_release, sharded_join) = hold_one_task(&sharded);
        let (unified_release, unified_join) = hold_one_task(&unified);
        assert_eq!(
            sharded.is_quiescent(),
            unified.is_quiescent(),
            "B02 quiescence parity while one task is live on each shape"
        );
        assert!(
            !unified.is_quiescent(),
            "unified shape reports non-quiescent with a live blocked task"
        );
        sharded_release.send(()).expect("release sharded task");
        unified_release.send(()).expect("release unified task");
        drop(sharded_join);
        drop(unified_join);

        // Drain both shapes to zero live tasks, then require quiescence
        // parity: B02 must consult shard A, not the empty embedded table.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let sharded_live = table
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .live_task_count();
            let unified_live = unified
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .live_task_count();
            if sharded_live == 0 && unified_live == 0 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "tasks drain to zero (sharded_live={sharded_live}, unified_live={unified_live})"
            );
            std::thread::yield_now();
        }
        let sharded_embedded_live = sharded
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .live_task_count();
        assert_eq!(
            sharded_embedded_live, 0,
            "the embedded table never owns sharded-shape tasks"
        );
        assert_eq!(
            sharded.is_quiescent(),
            unified.is_quiescent(),
            "B02 quiescence parity across shapes after identical workloads"
        );
    }

    /// E1.2 subsystem 3d: mailbox admission on the Sharded shape — the s1
    /// admission seam mints into shard A when workers drain the mailbox.
    #[test]
    fn sharded_shape_runtime_spawns_via_mailbox_and_quiesces() {
        init_test_logging();

        let mut config = RuntimeConfig::default();
        config.worker_threads = 2;
        config.runtime_state_shape = crate::runtime::config::RuntimeStateShape::Sharded;
        config.spawn_admission = crate::runtime::config::SpawnAdmissionMode::Mailbox;
        let runtime = Runtime::with_config_and_platform(
            config,
            None,
            None,
            None,
            None,
            &NativeThreadHostServices::new(),
        )
        .expect("sharded mailbox runtime constructs");
        let table = runtime
            .inner
            .scheduler
            .dispatch_task_table()
            .expect("sharded runtime dispatches against a task table");

        let (tx, rx) = std::sync::mpsc::channel();
        let handle = runtime.handle();
        let join = handle.spawn(async move {
            tx.send(7_u32).expect("send from sharded worker");
        });
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(10))
                .expect("mailbox-admitted task must dispatch from shard A"),
            7
        );
        drop(join);

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let live = table
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .live_task_count();
            if live == 0 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "shard A drains to quiescence ({live} live)"
            );
            std::thread::yield_now();
        }
        let embedded_live = runtime
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .live_task_count();
        assert_eq!(
            embedded_live, 0,
            "the embedded table never owns mailbox-admitted sharded tasks"
        );
    }

    /// E2 S4c-2c-iv (br-asupersync-m9wsza, fork option C): on the Sharded
    /// shape, obligations mint into and settle against shard C through the
    /// wrapper-side resolution — the embedded obligation table never owns
    /// them, the shard-C-reading counters observe the full lifecycle, and
    /// quiescence honors pending shard-C obligations.
    #[test]
    fn sharded_shape_obligations_mint_and_settle_in_shard_c() {
        init_test_logging();

        let mut config = RuntimeConfig::default();
        config.worker_threads = 1;
        config.runtime_state_shape = crate::runtime::config::RuntimeStateShape::Sharded;
        let runtime = Runtime::with_config_and_platform(
            config,
            None,
            None,
            None,
            None,
            &NativeThreadHostServices::new(),
        )
        .expect("sharded runtime constructs");
        let table = runtime
            .inner
            .scheduler
            .dispatch_task_table()
            .expect("sharded runtime dispatches against a task table");

        let mut state = runtime
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let root = state
            .root_region
            .expect("sharded runtime construction mints the root region");
        let region = state
            .create_child_region(root, crate::types::Budget::INFINITE)
            .expect("child region under the runtime root");

        // Mint the holder task into shard A the way sharded admission does:
        // the record lives in the dispatch table, never embedded.
        let holder = {
            let mut table_guard = table
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let idx = table_guard.insert_task(crate::record::TaskRecord::new(
                crate::types::TaskId::from_arena(crate::util::ArenaIndex::new(0, 0)),
                region,
                crate::types::Budget::INFINITE,
            ));
            let id = crate::types::TaskId::from_arena(idx);
            table_guard.task_mut(id).expect("holder record").id = id;
            id
        };
        state
            .region(region)
            .expect("root region")
            .add_task(holder)
            .expect("holder admission");

        let obligation = state
            .create_obligation(
                crate::record::ObligationKind::SendPermit,
                holder,
                region,
                Some("shard-c residency probe".to_string()),
            )
            .expect("sharded obligation mints via wrapper resolution");

        assert!(
            state.obligation(obligation).is_none(),
            "the embedded obligation table never owns sharded-shape obligations"
        );
        assert!(
            state.obligations_is_empty(),
            "embedded obligation table stays empty on the sharded shape"
        );
        assert_eq!(
            state.pending_obligation_count(),
            1,
            "the shard-C-reading counter observes the mint"
        );
        assert!(
            !state.is_quiescent(),
            "quiescence must honor pending shard-C obligations"
        );

        let duration = state
            .commit_obligation(obligation)
            .expect("sharded obligation commits via wrapper resolution");
        let _ = duration;
        assert_eq!(
            state.pending_obligation_count(),
            0,
            "the shard-C-reading counter observes the settle"
        );

        // The full reserve→commit trace pair rode the buffered drain.
        let events = state.trace.snapshot();
        let reserves = events
            .iter()
            .filter(|e| matches!(e.kind, crate::trace::TraceEventKind::ObligationReserve))
            .count();
        let commits = events
            .iter()
            .filter(|e| matches!(e.kind, crate::trace::TraceEventKind::ObligationCommit))
            .count();
        assert_eq!(reserves, 1, "reserve trace event dispatched post-release");
        assert_eq!(commits, 1, "commit trace event dispatched post-release");
        drop(state);
    }

    #[test]
    fn runtime_drop_interrupts_deadline_monitor_wait() {
        init_test_logging();

        let (host_services, started) = CoordinatedDeadlineMonitorHostServices::new();
        let mut config = RuntimeConfig::default();
        config.worker_threads = 1;
        config.deadline_monitor = Some(MonitorConfig {
            check_interval: Duration::from_secs(60),
            enabled: true,
            ..MonitorConfig::default()
        });

        let runtime =
            Runtime::with_config_and_platform(config, None, None, None, None, &host_services)
                .expect("runtime should start with the coordinated monitor host");
        started
            .recv_timeout(Duration::from_secs(1))
            .expect("coordinated monitor should enter its long wait promptly");

        let (drop_done_tx, drop_done_rx) = std::sync::mpsc::channel();
        let drop_thread = std::thread::spawn(move || {
            drop(runtime);
            let _ = drop_done_tx.send(());
        });

        if let Err(error) = drop_done_rx.recv_timeout(Duration::from_secs(1)) {
            host_services.rescue_shutdown();
            let _ = drop_thread.join();
            panic!("runtime drop did not interrupt the 60-second monitor wait: {error}");
        }
        drop_thread
            .join()
            .expect("runtime drop thread should exit cleanly");
    }

    /// Region-retained value that holds the runtime state (the cycle only
    /// teardown can break) and proves it is dropped outside the state lock.
    struct TeardownRetained {
        state: Arc<crate::sync::ContendedMutex<RuntimeState>>,
        dropped: Arc<AtomicUsize>,
        panic_on_drop: bool,
    }

    impl Drop for TeardownRetained {
        fn drop(&mut self) {
            drop(
                self.state
                    .try_lock()
                    .expect("retained value drops outside runtime lock"),
            );
            self.dropped.fetch_add(1, Ordering::SeqCst);
            assert!(
                !self.panic_on_drop,
                "injected retained-value destructor panic"
            );
        }
    }

    #[test]
    fn runtime_drop_releases_unapplied_region_finalizers_outside_state_lock() {
        struct WakeCounter(AtomicUsize);
        impl std::task::Wake for WakeCounter {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        let region = runtime.block_on(async {
            Cx::current()
                .unwrap()
                .open_child_region(crate::cx::ChildRegionSpec::inherit())
                .await
                .unwrap()
        });
        // Between block_on calls the background thread pumps region commands,
        // so an idle runtime applies them before teardown (the flake behind
        // asupersync-bi2462.147.11). Pin its only worker in a task until the
        // runtime starts stopping: the dispatch loop checks shutdown before
        // it drains region commands, so the requests below stay queued.
        let stopping = runtime.inner.scheduler.shutdown_signal_for_test();
        let (pinned_tx, pinned) = std::sync::mpsc::channel();
        let _pin = runtime.handle().spawn(async move {
            pinned_tx.send(()).expect("test thread waits for the pin");
            while !stopping.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
        });
        pinned
            .recv_timeout(Duration::from_secs(10))
            .expect("the background worker runs the pinning task");
        let state = Arc::clone(&runtime.inner.state);
        let dropped = Arc::new(AtomicUsize::new(0));
        let wake_count = Arc::new(WakeCounter(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wake_count));
        let mut context = std::task::Context::from_waker(&waker);
        let mut first = Box::pin(region.retain_until_finalized(TeardownRetained {
            state: Arc::clone(&state),
            dropped: Arc::clone(&dropped),
            panic_on_drop: true,
        }));
        let mut second = Box::pin(region.retain_until_finalized(TeardownRetained {
            state,
            dropped: Arc::clone(&dropped),
            panic_on_drop: false,
        }));
        assert!(first.as_mut().poll(&mut context).is_pending());
        assert!(second.as_mut().poll(&mut context).is_pending());
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        assert_eq!(wake_count.0.load(Ordering::SeqCst), 0);

        // Both requests remain queued, and the child region plus retained
        // state keep the mailbox reachable.
        drop(runtime);
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
        assert!(wake_count.0.load(Ordering::SeqCst) >= 2);
        assert!(matches!(
            first.as_mut().poll(&mut context),
            Poll::Ready(Err(crate::cx::ChildRegionError::RuntimeUnavailable))
        ));
        assert!(matches!(
            second.as_mut().poll(&mut context),
            Poll::Ready(Err(crate::cx::ChildRegionError::RuntimeUnavailable))
        ));
        eprintln!(
            "REGION_FINALIZER_TEARDOWN backend=native queued=2 retired=2 acknowledgments=closed locks=reentrant"
        );
    }

    #[test]
    fn runtime_drop_releases_applied_region_finalizers_outside_state_lock() {
        for sharded in [false, true] {
            let runtime = RuntimeBuilder::current_thread()
                .with_sharded_state(sharded)
                .build()
                .unwrap();
            let state = Arc::clone(&runtime.inner.state);
            let dropped = Arc::new(AtomicUsize::new(0));
            let retained = [true, false].map(|panic_on_drop| TeardownRetained {
                state: Arc::clone(&state),
                dropped: Arc::clone(&dropped),
                panic_on_drop,
            });
            drop(state);
            let region = runtime.block_on(async move {
                let region = Cx::current()
                    .unwrap()
                    .open_child_region(crate::cx::ChildRegionSpec::inherit())
                    .await
                    .unwrap();
                for value in retained {
                    region
                        .retain_until_finalized(value)
                        .await
                        .expect("an open region admits the finalizer");
                }
                region
            });
            // Both values are applied to the open region's finalizer stack and
            // each keeps the runtime state alive: only teardown can drop them.
            assert_eq!(dropped.load(Ordering::SeqCst), 0);
            drop(runtime);
            assert_eq!(
                dropped.load(Ordering::SeqCst),
                2,
                "sharded={sharded}: teardown must release admitted finalizers"
            );
            drop(region);
            eprintln!(
                "REGION_FINALIZER_TEARDOWN backend=native sharded={sharded} applied=2 released=2 locks=reentrant"
            );
        }
    }

    #[test]
    fn native_runtime_keeps_admitting_child_regions_after_a_thousand_have_closed() {
        init_test_logging();
        // The swarm governor admits Normal-priority regions against its live
        // envelope count (default cap 1000). Every closed region must release
        // its envelope, or the 1001st open is refused (asupersync-cgnb7g).
        let rounds = 1_100_usize;
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        let opened = runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().expect("admitted native task");
            let mut opened = 0_usize;
            for round in 0..rounds {
                let region = match cx
                    .open_child_region(crate::cx::ChildRegionSpec::inherit())
                    .await
                {
                    Ok(region) => region,
                    Err(error) => panic!("child region {round} refused: {error:?}"),
                };
                region.close().await.expect("child region closes");
                opened += 1;
            }
            opened
        }));
        eprintln!("native_region_admission rounds={rounds} opened={opened}");
        assert_eq!(opened, rounds);
    }

    #[test]
    fn native_runtime_bounds_region_and_race_oracle_history() {
        init_test_logging();
        // Every round closes a child region and completes a drain-correct race.
        // Unbounded, each round appended to both histories for the life of the
        // runtime.
        let rounds = 2 * NATIVE_ORACLE_HISTORY_LIMIT + 64;
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().expect("admitted native task");
            for round in 0..rounds {
                let region = cx
                    .open_child_region(crate::cx::ChildRegionSpec::inherit())
                    .await
                    .expect("child region opens");
                region.close().await.expect("child region closes");
                let branch = move |_child: Cx| -> Pin<Box<dyn Future<Output = usize> + Send>> {
                    Box::pin(async move { round })
                };
                let factories: Vec<crate::cx::RaceFactory<usize>> =
                    vec![Box::new(branch), Box::new(branch)];
                let winner = cx
                    .race_drained_with(factories)
                    .await
                    .expect("race completes");
                assert_eq!(winner, round);
            }
        }));
        let state = runtime
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let races = state
            .loser_drain_history()
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    crate::runtime::state::LoserDrainHistoryEvent::RaceStarted { .. }
                )
            })
            .count();
        let closed = state
            .finalizer_history()
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    crate::runtime::state::FinalizerHistoryEvent::RegionClosed { .. }
                )
            })
            .count();
        drop(state);
        eprintln!(
            "native_oracle_history rounds={rounds} races_kept={races} closed_regions_kept={closed} limit={NATIVE_ORACLE_HISTORY_LIMIT}"
        );
        let recent_tail = NATIVE_ORACLE_HISTORY_LIMIT..=2 * NATIVE_ORACLE_HISTORY_LIMIT;
        assert!(
            recent_tail.contains(&races),
            "races kept: {races} of {rounds}"
        );
        assert!(
            recent_tail.contains(&closed),
            "closed regions kept: {closed} of {rounds}"
        );
    }

    #[test]
    fn native_deadline_monitor_releases_runtime_state_before_warning_callback() {
        init_test_logging();

        let state = Arc::new(crate::sync::ContendedMutex::new(
            "runtime_state",
            RuntimeState::new(),
        ));
        {
            let mut guard = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let region = guard.create_root_region(Budget::INFINITE);
            guard.now = Time::from_secs(100);
            let budget = Budget::new().with_deadline(Time::from_secs(110));
            let idx = guard.insert_task_with(|idx| {
                let task_id = crate::types::TaskId::from_arena(idx);
                let mut record = TaskRecord::new_with_time(
                    task_id,
                    region,
                    budget,
                    Time::from_nanos(1_000_000_000),
                );
                let mut inner = CxInner::new(region, task_id, budget);
                inner.checkpoint_state.last_checkpoint = Some(Time::from_nanos(1_000_000_000));
                inner.checkpoint_state.checkpoint_count = 1;
                record.set_cx_inner(Arc::new(RwLock::new(inner)));
                record
            });
            let task_id = crate::types::TaskId::from_arena(idx);
            guard
                .regions
                .get(region.arena_index())
                .expect("root region exists")
                .add_task(task_id)
                .expect("task admission succeeds");
        }

        let (tx, rx) = std::sync::mpsc::channel();
        let state_for_handler = Arc::clone(&state);
        let mut config = RuntimeConfig::default();
        config.thread_name_prefix = "deadline-monitor-test".to_string();
        config.deadline_monitor = Some(MonitorConfig {
            check_interval: Duration::from_millis(1),
            warning_threshold_fraction: 0.2,
            checkpoint_timeout: Duration::from_millis(1),
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: true,
        });
        config.deadline_warning_handler = Some(Arc::new(move |_| {
            let reacquired = state_for_handler.try_lock().is_ok();
            let _ = tx.send(reacquired);
        }));

        let service = NativeThreadHostServices::start_deadline_monitor(&config, &state, None);
        let reacquired = rx
            .recv_timeout(Duration::from_secs(1))
            .expect("deadline warning callback should fire");

        if let Some(shutdown) = service.shutdown.as_ref() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = service.thread {
            thread.join().expect("deadline monitor thread should stop");
        }

        assert!(
            reacquired,
            "warning callback must run after dropping the runtime-state lock"
        );
    }

    #[derive(Clone)]
    struct NativeDeadlineMetrics {
        completions: std::sync::mpsc::Sender<(String, Duration)>,
        state: Arc<Mutex<Option<std::sync::Weak<crate::sync::ContendedMutex<RuntimeState>>>>>,
        panic_remaining: bool,
    }

    impl MetricsProvider for NativeDeadlineMetrics {
        fn task_spawned(&self, _: RegionId, _: TaskId) {}
        fn task_completed(
            &self,
            _: TaskId,
            _: crate::observability::metrics::OutcomeKind,
            _: Duration,
        ) {
        }
        fn region_created(&self, _: RegionId, _: Option<RegionId>) {}
        fn region_closed(&self, _: RegionId, _: Duration) {}
        fn cancellation_requested(&self, _: RegionId, _: crate::types::CancelKind) {}
        fn drain_completed(&self, _: RegionId, _: Duration) {}
        fn deadline_set(&self, _: RegionId, _: Duration) {}
        fn deadline_exceeded(&self, _: RegionId) {}
        fn deadline_warning(&self, _: &str, _: &'static str, _: Duration) {}
        fn deadline_violation(&self, _: &str, _: Duration) {}
        fn checkpoint_interval(&self, _: &str, _: Duration) {}
        fn task_stuck_detected(&self, _: &str) {}
        fn obligation_created(&self, _: RegionId) {}
        fn obligation_discharged(&self, _: RegionId) {}
        fn obligation_leaked(&self, _: RegionId) {}
        fn scheduler_tick(&self, _: usize, _: Duration) {}

        fn deadline_remaining(&self, task_type: &str, remaining: Duration) {
            let state = self.state.lock().as_ref().and_then(std::sync::Weak::upgrade);
            if let Some(state) = state {
                // A real re-entry: this would deadlock if native delivery kept
                // the runtime-state lock from snapshot or task completion.
                drop(state.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
            }
            self.completions
                .send((task_type.to_string(), remaining))
                .expect("completion observation receiver remains alive");
            assert!(!self.panic_remaining, "injected native deadline metric panic");
        }
    }

    fn native_deadline_metrics(
        panic_remaining: bool,
    ) -> (
        NativeDeadlineMetrics,
        std::sync::mpsc::Receiver<(String, Duration)>,
    ) {
        let (completions, receiver) = std::sync::mpsc::channel();
        (
            NativeDeadlineMetrics {
                completions,
                state: Arc::new(Mutex::new(None)),
                panic_remaining,
            },
            receiver,
        )
    }

    #[test]
    fn native_task_completions_teach_adaptive_deadline_warnings() {
        use crate::channel::oneshot;

        for sharded in [false, true] {
            let (metrics, completions) = native_deadline_metrics(false);
            let (warnings_tx, warnings_rx) = std::sync::mpsc::channel();
            let builder = if sharded {
                RuntimeBuilder::new().worker_threads(2).with_sharded_state(true)
            } else {
                RuntimeBuilder::current_thread()
            };
            let runtime = builder
                .metrics(metrics.clone())
                .deadline_monitoring(|monitor| {
                    monitor
                        .check_interval(Duration::from_millis(5))
                        .checkpoint_timeout(Duration::from_secs(60))
                        .adaptive_enabled(true)
                        .adaptive_min_samples(1)
                        .adaptive_fallback_threshold(Duration::from_secs(60))
                        .on_warning(move |warning| {
                            warnings_tx.send(warning.task_id).expect("warning receiver");
                        })
                })
                .build()
                .unwrap();
            *metrics.state.lock() = Some(Arc::downgrade(&runtime.inner.state));
            let cx = runtime.request_cx_with_budget(Budget::INFINITE);
            let scope = cx.scope_with_budget(cx.budget_for_timeout(Duration::from_secs(60)));
            let mut training = cx
                .spawn_in(&scope, |child| async move {
                    child.set_task_type("native.learn");
                    42usize
                })
                .unwrap();
            assert_eq!(runtime.block_on(training.join(&cx)), Ok(42));
            assert_eq!(
                completions.recv_timeout(Duration::from_secs(2)).unwrap().0,
                "native.learn",
            );

            let (parked_tx, mut parked_rx) = oneshot::channel();
            let (release_tx, mut release_rx) = oneshot::channel::<()>();
            let mut waiting = cx
                .spawn_in(&scope, move |child| async move {
                    child.set_task_type("native.learn");
                    let mut receive = Box::pin(release_rx.recv(&child));
                    std::future::poll_fn(|task_cx| {
                        assert!(receive.as_mut().poll(task_cx).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    parked_tx.send_blocking(()).expect("parked witness");
                    receive.await.expect("release the monitored child");
                })
                .unwrap();
            runtime.block_on(parked_rx.recv(&cx)).unwrap();
            assert_eq!(release_tx.telemetry_snapshot(0).recv_waiter_count, 1);
            let warning = warnings_rx.recv_timeout(Duration::from_secs(2));
            // Release and drain even when the warning is missing, so failure
            // does not leave a parked child behind the assertion.
            release_tx.send_blocking(()).unwrap();
            runtime.block_on(waiting.join(&cx)).unwrap();
            assert_eq!(warning.unwrap(), waiting.task_id());
            assert_eq!(
                completions.recv_timeout(Duration::from_secs(2)).unwrap().0,
                "native.learn",
            );
            assert_eq!(runtime.deadline_monitor_stats().unwrap().dropped_completions, 0);
            assert_eq!(
                runtime.shutdown_drained(Duration::from_secs(2)).outcome,
                RootDrainOutcome::Quiescent,
            );
        }
    }

    #[test]
    fn native_deadline_monitor_shutdown_drains_unscanned_completions_despite_callback_panics() {
        for sharded in [false, true] {
            for panic_remaining in [false, true] {
                let (metrics, completions) = native_deadline_metrics(panic_remaining);
                let builder = if sharded {
                    RuntimeBuilder::new().worker_threads(2).with_sharded_state(true)
                } else {
                    RuntimeBuilder::current_thread()
                };
                let runtime = builder
                    .metrics(metrics.clone())
                    .deadline_monitoring(|monitor| monitor.check_interval(Duration::from_secs(60)))
                    .build()
                    .unwrap();
                *metrics.state.lock() = Some(Arc::downgrade(&runtime.inner.state));
                let queue = runtime
                    .inner
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .deadline_completions()
                    .unwrap();
                let cx = runtime.request_cx_with_budget(Budget::INFINITE);
                let scope = cx.scope_with_budget(cx.budget_for_timeout(Duration::from_secs(30)));
                let handles = cx
                    .spawn_batch_in(&scope, (0..4usize).map(|value| {
                        move |child: Cx| async move {
                            child.set_task_type("native.shutdown");
                            value
                        }
                    }))
                    .unwrap();
                runtime.block_on(async {
                    for (expected, mut handle) in handles.into_iter().enumerate() {
                        assert_eq!(handle.join(&cx).await.unwrap(), expected);
                    }
                });
                assert_eq!(
                    runtime.shutdown_drained(Duration::from_secs(2)).outcome,
                    RootDrainOutcome::Quiescent,
                );
                drop(runtime);
                let final_stats = queue.stats();
                assert!(final_stats.closed);
                assert_eq!(final_stats.accepted_completions, 4);
                assert_eq!(final_stats.processed_completions, 4);
                assert_eq!(final_stats.queued_completions, 0);
                assert_eq!(final_stats.dropped_completions, 0);
                assert_eq!(final_stats.rejected_after_shutdown, 0);
                assert_eq!(final_stats.callback_panics, if panic_remaining { 4 } else { 0 });
                let observed: Vec<_> = completions.try_iter().collect();
                assert_eq!(observed.len(), 4);
                assert!(observed.iter().all(|(label, _)| label == "native.shutdown"));
            }
        }
    }

    #[test]
    fn disabled_native_deadline_monitor_does_not_install_a_completion_queue() {
        let runtime = RuntimeBuilder::current_thread()
            .deadline_monitoring(|monitor| monitor.enabled(false))
            .build()
            .unwrap();
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let mut handle = cx.spawn(|_| std::future::ready(17usize)).unwrap();
        assert_eq!(runtime.block_on(handle.join(&cx)), Ok(17));
        assert!(runtime.deadline_monitor_stats().is_none());
    }

    /// E1.2 step 4 (parent AC 4 / bead AC 3,
    /// br-asupersync-sched-hot-path-perf-bt4y5f.2.2): semantics-identical
    /// proof across `RuntimeStateShape::Unified|Sharded`. A fixed,
    /// fully-serialized workload corpus (spawn ordering rendezvoused through
    /// channels so task-identity assignment cannot race worker activity) must
    /// produce byte-identical canonical semantic trace fingerprints on both
    /// shapes: the same task identities, spawn/completion lifecycle events,
    /// and region transitions. Poll/schedule/wake events are excluded by
    /// design — they encode scheduling, not semantics.
    #[test]
    fn unified_and_sharded_shapes_produce_identical_semantic_trace_fingerprints() {
        init_test_logging();

        fn drain_to_zero_live(runtime: &Runtime) {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                let embedded = runtime
                    .inner
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .live_task_count();
                let dispatch = runtime
                    .inner
                    .scheduler
                    .dispatch_task_table()
                    .map_or(0, |table| {
                        table
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .live_task_count()
                    });
                if embedded == 0 && dispatch == 0 {
                    return;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "corpus drains to zero live tasks (embedded={embedded}, dispatch={dispatch})"
                );
                std::thread::yield_now();
            }
        }

        fn run_corpus_and_fingerprint(
            shape: crate::runtime::config::RuntimeStateShape,
            worker_threads: usize,
        ) -> Vec<String> {
            let mut config = RuntimeConfig::default();
            config.worker_threads = worker_threads;
            config.runtime_state_shape = shape;
            let runtime = Runtime::with_config_and_platform(
                config,
                None,
                None,
                None,
                None,
                &NativeThreadHostServices::new(),
            )
            .expect("corpus runtime constructs");
            let handle = runtime.handle();

            // Phase 1: six ok tasks, one at a time (each spawn waits for the
            // prior completion signal, so arena minting order is total).
            for i in 0..6_u32 {
                let (tx, rx) = std::sync::mpsc::channel();
                let join = handle.spawn(async move {
                    tx.send(i).expect("corpus send");
                });
                assert_eq!(
                    rx.recv_timeout(Duration::from_secs(10))
                        .expect("corpus recv"),
                    i
                );
                drop(join);
            }
            drain_to_zero_live(&runtime);

            // Phase 2: one panicking task (ordered panic-completion arm).
            let join = handle.spawn(async {
                panic!("deliberate corpus panic");
            });
            drop(join);
            drain_to_zero_live(&runtime);

            // Phase 3: worker-side nested spawn (fire-and-forget child).
            let (tx, rx) = std::sync::mpsc::channel();
            let join = handle.spawn(async move {
                let nested = Runtime::current_handle()
                    .expect("worker thread carries the runtime handle")
                    .spawn(async move {
                        tx.send(100_u32).expect("nested send");
                    });
                drop(nested);
            });
            assert_eq!(
                rx.recv_timeout(Duration::from_secs(10))
                    .expect("nested child ran"),
                100
            );
            drop(join);
            drain_to_zero_live(&runtime);

            // Phase 3.5: two-phase channel permits on a runtime-linked Cx
            // (one committed via reserve → send, one aborted via reserve →
            // drop). NOTE (recorded finding): production mpsc permits are
            // channel-internal two-phase accounting — they do NOT register
            // in the RuntimeState obligation table, and no
            // ObligationReserve/Commit/Abort trace events are emitted from
            // this surface (the traced registry is used by remote
            // leases/lab surfaces). The phase still exercises the permit
            // lifecycle across shapes; the fingerprint's obligation arm
            // stays wired for future registry-surface corpus extensions.
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            handle.spawn_with_cx(move |cx| async move {
                let (tx, _rx) = crate::channel::mpsc::channel::<u32>(4);
                let permit = tx.reserve(&cx).await.expect("reserve commit permit");
                permit.send(11);
                let aborted = tx.reserve(&cx).await.expect("reserve abort permit");
                drop(aborted);
                done_tx.send(()).expect("obligation phase done");
            });
            done_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("obligation phase completed");
            drain_to_zero_live(&runtime);

            // Phase 4: shutdown cancellation. A pending-forever task is live
            // when the runtime drops; both shapes must retire it through the
            // same shutdown semantics. The trace handle is cloned first (the
            // buffer is Arc-shared) so events emitted during shutdown are
            // captured after the runtime is gone.
            let trace = runtime
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .trace_handle();
            let (started_tx, started_rx) = std::sync::mpsc::channel();
            let join = handle.spawn(async move {
                started_tx.send(()).expect("signal pending task started");
                std::future::pending::<()>().await;
            });
            started_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("pending task reached its first poll");
            drop(join);
            drop(handle);
            drop(runtime);

            let events = trace.snapshot();
            // br-asupersync-xh4efw: per-task causal seq contract — a task's
            // Spawn seq precedes its Complete seq on both shapes and worker
            // counts. Spawn-effect seqs are allocated at admission (under
            // the state lock, before injection) precisely so this holds
            // under the deferred-dispatch race br-asupersync-7amdgn
            // exposed; the two-pass canonicalization below tolerates any
            // order, so this assertion is the contract's dedicated proof.
            {
                let mut spawn_seqs: std::collections::HashMap<String, u64> =
                    std::collections::HashMap::new();
                for event in &events {
                    if let (
                        crate::trace::TraceEventKind::Spawn,
                        crate::trace::TraceData::Task { task, .. },
                    ) = (&event.kind, &event.data)
                    {
                        spawn_seqs.insert(format!("{task:?}"), event.seq);
                    }
                }
                for event in &events {
                    if let (
                        crate::trace::TraceEventKind::Complete,
                        crate::trace::TraceData::Task { task, .. },
                    ) = (&event.kind, &event.data)
                    {
                        if let Some(spawn_seq) = spawn_seqs.get(&format!("{task:?}")) {
                            assert!(
                                *spawn_seq < event.seq,
                                "task {task:?}: Spawn seq {spawn_seq} must precede \
                                 Complete seq {} (shape={shape:?}, \
                                 workers={worker_threads})",
                                event.seq
                            );
                        }
                    }
                }
            }
            // Canonicalize task identity by spawn order: the corpus is fully
            // serialized, so spawn order is deterministic on both shapes,
            // while physical arena (slot, generation) assignment depends on
            // a benign completion/spawn recycle race and differs across
            // shapes AND across runs. Slot reuse is an allocation detail; a
            // real semantic divergence (task count, completion set, region
            // linkage, a Complete without a Spawn) stays visible.
            //
            // The spawn->ordinal map is built in a dedicated pass over ALL
            // events BEFORE any Complete is resolved (br-asupersync-7amdgn):
            // production spawn effects dispatch outside runtime locks AFTER
            // the task is injected, so a fast worker can record a task's
            // Complete into the shared trace buffer before the spawning
            // thread records its Spawn — the two events' seq order inverts.
            // That inversion is a property of the deferred spawn-effects
            // design on BOTH shapes (whichever side wins the buffer race),
            // not a semantic divergence; a single forward pass misread such
            // completes as UNSPAWNED. A Complete whose id appears in NO
            // Spawn event anywhere in the trace still fails closed via the
            // UNSPAWNED arm below. The sorted fingerprint never asserted
            // intra-task event order to begin with.
            let mut canonical: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();
            for event in &events {
                if let (
                    crate::trace::TraceEventKind::Spawn,
                    crate::trace::TraceData::Task { task, .. },
                ) = (&event.kind, &event.data)
                {
                    let next = canonical.len();
                    canonical.entry(format!("{task:?}")).or_insert(next);
                }
            }
            let mut fingerprint: Vec<String> = Vec::new();
            for event in &events {
                match (&event.kind, &event.data) {
                    (
                        crate::trace::TraceEventKind::Spawn,
                        crate::trace::TraceData::Task { task, region },
                    ) => {
                        let ordinal = canonical
                            .get(&format!("{task:?}"))
                            .expect("spawn ids were interned in the first pass");
                        fingerprint.push(format!("Spawn|T{ordinal}|{region:?}"));
                    }
                    (
                        crate::trace::TraceEventKind::Complete,
                        crate::trace::TraceData::Task { task, region },
                    ) => match canonical.get(&format!("{task:?}")) {
                        Some(ordinal) => {
                            fingerprint.push(format!("Complete|T{ordinal}|{region:?}"));
                        }
                        None => {
                            fingerprint.push(format!("Complete|UNSPAWNED({task:?})|{region:?}"));
                        }
                    },
                    (
                        crate::trace::TraceEventKind::RegionCreated
                        | crate::trace::TraceEventKind::RegionCloseBegin
                        | crate::trace::TraceEventKind::RegionCloseComplete
                        | crate::trace::TraceEventKind::RegionCancelled,
                        crate::trace::TraceData::Region { region, parent },
                    ) => {
                        fingerprint.push(format!("{:?}|{region:?}|{parent:?}", event.kind));
                    }
                    (
                        crate::trace::TraceEventKind::ObligationReserve
                        | crate::trace::TraceEventKind::ObligationCommit
                        | crate::trace::TraceEventKind::ObligationAbort
                        | crate::trace::TraceEventKind::ObligationLeak,
                        crate::trace::TraceData::Obligation {
                            task,
                            kind,
                            abort_reason,
                            ..
                        },
                    ) => {
                        // Obligation arena ids carry the same slot-reuse
                        // hazard as task ids; identity rides the holder's
                        // canonical ordinal + obligation kind instead.
                        let holder = canonical
                            .get(&format!("{task:?}"))
                            .map_or_else(|| format!("UNSPAWNED({task:?})"), |o| format!("T{o}"));
                        fingerprint.push(format!(
                            "{:?}|{holder}|{kind:?}|{abort_reason:?}",
                            event.kind
                        ));
                    }
                    _ => {}
                }
            }
            fingerprint.sort();
            fingerprint
        }

        let corpus = |worker_threads: usize| {
            let unified = run_corpus_and_fingerprint(
                crate::runtime::config::RuntimeStateShape::Unified,
                worker_threads,
            );
            let sharded = run_corpus_and_fingerprint(
                crate::runtime::config::RuntimeStateShape::Sharded,
                worker_threads,
            );

            // Fail-closed guards: an empty fingerprint would make the
            // equality below vacuous. The corpus mints 11 tasks (6 ok +
            // panic + parent + child + permit-lifecycle task + shutdown
            // pending task), each with a Spawn event. The production mpsc
            // permit phase emits no Obligation* trace events (permits are
            // channel-internal two-phase accounting, not registry
            // obligations); the obligation fingerprint arm stays wired for
            // registry-surface corpus extensions.
            let unified_spawns = unified
                .iter()
                .filter(|line| line.starts_with("Spawn|"))
                .count();
            assert!(
                unified_spawns >= 11,
                "fingerprint must capture the corpus spawns \
                 (workers={worker_threads}, got {unified_spawns})"
            );
            assert_eq!(
                unified, sharded,
                "semantic trace fingerprints must be identical across \
                 RuntimeStateShape::Unified and RuntimeStateShape::Sharded \
                 (workers={worker_threads})"
            );
        };
        corpus(1);
        corpus(2);
    }

    /// E1.2 subsystem 3d (E1.1 row B01): the deadline monitor must snapshot
    /// deadlines from the dispatch task table — a dispatch-table runtime's
    /// live tasks are invisible to the embedded scan alone.
    #[test]
    fn native_deadline_monitor_scans_dispatch_task_table() {
        init_test_logging();

        let state = Arc::new(crate::sync::ContendedMutex::new(
            "runtime_state",
            RuntimeState::new(),
        ));
        let table = Arc::new(crate::sync::ContendedMutex::new(
            "task_table",
            crate::runtime::TaskTable::new(),
        ));
        {
            let mut guard = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let region = guard.create_root_region(Budget::INFINITE);
            guard.now = Time::from_secs(100);
            let budget = Budget::new().with_deadline(Time::from_secs(110));
            let idx = {
                let mut tt = table
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                tt.insert_task_with(|idx| {
                    let task_id = crate::types::TaskId::from_arena(idx);
                    let mut record = TaskRecord::new_with_time(
                        task_id,
                        region,
                        budget,
                        Time::from_nanos(1_000_000_000),
                    );
                    let mut inner = CxInner::new(region, task_id, budget);
                    inner.checkpoint_state.last_checkpoint = Some(Time::from_nanos(1_000_000_000));
                    inner.checkpoint_state.checkpoint_count = 1;
                    record.set_cx_inner(Arc::new(RwLock::new(inner)));
                    record
                })
            };
            let task_id = crate::types::TaskId::from_arena(idx);
            guard
                .regions
                .get(region.arena_index())
                .expect("root region exists")
                .add_task(task_id)
                .expect("task admission succeeds");
        }

        let (tx, rx) = std::sync::mpsc::channel();
        let mut config = RuntimeConfig::default();
        config.thread_name_prefix = "deadline-monitor-shard-test".to_string();
        config.deadline_monitor = Some(MonitorConfig {
            check_interval: Duration::from_millis(1),
            warning_threshold_fraction: 0.2,
            checkpoint_timeout: Duration::from_millis(1),
            adaptive: AdaptiveDeadlineConfig::default(),
            enabled: true,
        });
        config.deadline_warning_handler = Some(Arc::new(move |_| {
            let _ = tx.send(());
        }));

        let service = NativeThreadHostServices::start_deadline_monitor(
            &config,
            &state,
            Some(Arc::clone(&table)),
        );
        let fired = rx.recv_timeout(Duration::from_secs(1));

        if let Some(shutdown) = service.shutdown.as_ref() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = service.thread {
            thread.join().expect("deadline monitor thread should stop");
        }

        fired.expect(
            "deadline warning must fire from the dispatch-table scan — the \
             embedded table holds no record for this task",
        );
    }

    #[test]
    fn runtime_handle_spawn_completes_via_scheduler() {
        init_test_logging();
        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .build()
            .expect("runtime build");

        let flag = Arc::new(AtomicBool::new(false));
        let flag_clone = Arc::clone(&flag);

        let handle = runtime.handle().spawn(async move {
            flag_clone.store(true, Ordering::SeqCst);
            42u32
        });

        let result = runtime.block_on(handle);
        assert_eq!(result, 42);
        assert!(flag.load(Ordering::SeqCst));
    }

    #[test]
    fn spawn_with_cx_factory_reenters_after_publication_and_panic_does_not_kill_worker() {
        init_test_logging();
        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .spawn_admission(crate::runtime::config::SpawnAdmissionMode::Direct)
            .build()
            .expect("runtime build");
        let state = Arc::clone(&runtime.inner.state);
        let (observation_tx, observation_rx) = std::sync::mpsc::channel();

        runtime
            .handle()
            .try_spawn_with_cx(move |cx| -> std::future::Ready<()> {
                let observation = state.try_lock().ok().and_then(|runtime| {
                    runtime.task(cx.task_id()).map(|record| {
                        record
                            .cx_inner
                            .as_ref()
                            .is_some_and(|inner| inner.read().runnable_publication.is_published())
                    })
                });
                observation_tx
                    .send(observation)
                    .expect("report first-poll state");
                panic!("synchronous spawn_with_cx factory panic");
            })
            .expect("task must publish before factory execution");

        assert_eq!(
            observation_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("factory should reach first poll"),
            Some(true),
            "factory must run outside the state lock after runnable publication"
        );

        let (alive_tx, alive_rx) = std::sync::mpsc::channel();
        let heartbeat = runtime.handle().spawn(async move {
            alive_tx.send(()).expect("worker heartbeat");
        });
        alive_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("contained factory panic must leave the worker alive");
        runtime.block_on(heartbeat);
        wait_for_runtime_quiescent(&runtime);
    }

    #[test]
    fn runtime_spawn_blocking_executes_on_pool() {
        init_test_logging();
        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .blocking_threads(1, 2)
            .build()
            .expect("runtime build");

        let flag = Arc::new(AtomicBool::new(false));
        let flag_clone = Arc::clone(&flag);

        // Spawn blocking task via runtime
        let handle = runtime
            .spawn_blocking(move || {
                flag_clone.store(true, Ordering::SeqCst);
            })
            .expect("blocking pool configured");

        // Wait for completion
        handle.wait();
        assert!(flag.load(Ordering::SeqCst), "blocking task should have run");
    }

    #[test]
    fn runtime_without_blocking_pool_returns_none() {
        init_test_logging();
        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .blocking_threads(0, 0)
            .build()
            .expect("runtime build");

        let handle = runtime.spawn_blocking(|| {});
        assert!(
            handle.is_none(),
            "spawn_blocking should return None when pool is not configured"
        );
        assert!(
            runtime.blocking_handle().is_none(),
            "blocking_handle should return None"
        );
    }

    /// br-asupersync-issue65-criticisms-kpmoy5.1.15: without a pool,
    /// `spawn_blocking` runs the closure inline on the thread that polls it.
    #[test]
    fn a_bare_builder_runs_blocking_work_on_a_default_pool_thread() {
        init_test_logging();
        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .build()
            .expect("runtime build");
        let pool = runtime
            .blocking_handle()
            .expect("a bare builder configures an on-demand pool");
        assert_eq!(pool.current_max_threads(), DEFAULT_BLOCKING_MAX_THREADS);
        assert_eq!(pool.active_threads(), 0, "no pool thread starts before use");
        assert!(
            !pool.is_explicitly_sized(),
            "the default pool's cap must not stand in for a CPU count"
        );

        let ran_on = runtime.block_on(crate::runtime::spawn_blocking(|| {
            std::thread::current().name().map(str::to_owned)
        }));
        assert!(
            ran_on
                .as_deref()
                .is_some_and(|name| name.contains("-blocking-")),
            "the closure must run on a pool thread, not inline: {ran_on:?}"
        );
    }

    #[test]
    fn a_named_blocking_size_marks_the_pool_explicit() {
        init_test_logging();
        for builder in [
            RuntimeBuilder::new().blocking_threads(0, DEFAULT_BLOCKING_MAX_THREADS),
            RuntimeBuilder::current_thread().blocking_threads(1, 4),
        ] {
            let runtime = builder.build().expect("runtime build");
            let pool = runtime.blocking_handle().expect("a named size > 0");
            assert!(pool.is_explicitly_sized());
        }
        with_envs(
            &[(crate::runtime::env_config::ENV_BLOCKING_MAX_THREADS, "8")],
            || {
                let runtime = RuntimeBuilder::new()
                    .with_env_overrides()
                    .expect("env overrides")
                    .build()
                    .expect("runtime build");
                let pool = runtime.blocking_handle().expect("env-sized pool");
                assert_eq!(pool.current_max_threads(), 8);
                assert!(pool.is_explicitly_sized());
            },
        );
        with_envs(
            &[(crate::runtime::env_config::ENV_BLOCKING_MIN_THREADS, "1")],
            || {
                let runtime = RuntimeBuilder::new()
                    .with_env_overrides()
                    .expect("env overrides")
                    .build()
                    .expect("runtime build");
                let pool = runtime.blocking_handle().expect("default pool");
                assert_eq!(pool.current_max_threads(), DEFAULT_BLOCKING_MAX_THREADS);
                assert!(
                    !pool.is_explicitly_sized(),
                    "a minimum alone leaves the default maximum"
                );
            },
        );
    }

    #[test]
    fn runtime_builder_platform_seams_propagate_into_task_contexts() {
        init_test_logging();

        let io_driver = IoDriverHandle::new(Arc::new(LabReactor::new()));
        {
            let mut driver = io_driver.lock();
            let _ = driver.register_waker(noop_waker());
        }

        let virtual_clock = Arc::new(crate::time::VirtualClock::starting_at(Time::from_secs(42)));
        let timer_driver = TimerDriverHandle::with_virtual_clock(virtual_clock);

        let runtime = RuntimeBuilder::current_thread()
            .with_io_driver(io_driver)
            .with_timer_driver(timer_driver)
            .with_entropy_source(Arc::new(crate::util::DetEntropy::new(1234)))
            .build()
            .expect("runtime build");

        let (io_present, timer_now, entropy_source) =
            runtime.block_on(runtime.handle().spawn(async {
                let cx = Cx::current().expect("task context");
                (
                    cx.io_driver_handle().is_some(),
                    cx.timer_driver().map(|driver| driver.now()),
                    cx.entropy().source_id(),
                )
            }));
        assert!(io_present, "injected io driver should be visible in Cx");
        assert_eq!(
            timer_now,
            Some(Time::from_secs(42)),
            "injected virtual timer should be visible in Cx"
        );
        assert_eq!(
            entropy_source, "deterministic",
            "injected entropy source should flow through Cx"
        );

        let guard = runtime
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let state_io = guard.io_driver_handle().expect("runtime io driver");
        assert_eq!(
            state_io.waker_count(),
            1,
            "runtime should retain the injected io driver instance"
        );
        let state_timer = guard.timer_driver_handle().expect("runtime timer driver");
        assert_eq!(
            state_timer.now(),
            Time::from_secs(42),
            "runtime should retain the injected timer driver instance"
        );
        drop(guard);
    }

    #[test]
    fn runtime_builder_platform_seams_override_reactor_defaults() {
        init_test_logging();

        let custom_driver = IoDriverHandle::new(Arc::new(LabReactor::new()));
        {
            let mut driver = custom_driver.lock();
            let _ = driver.register_waker(noop_waker());
        }
        let custom_timer = TimerDriverHandle::with_virtual_clock(Arc::new(
            crate::time::VirtualClock::starting_at(Time::from_secs(7)),
        ));

        let runtime = RuntimeBuilder::current_thread()
            .with_reactor(Arc::new(LabReactor::new()))
            .with_io_driver(custom_driver)
            .with_timer_driver(custom_timer)
            .build()
            .expect("runtime build");

        let guard = runtime
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let io = guard.io_driver_handle().expect("io driver");
        assert_eq!(
            io.waker_count(),
            1,
            "explicit io driver should override default reactor wiring"
        );
        let timer = guard.timer_driver_handle().expect("timer driver");
        assert_eq!(
            timer.now(),
            Time::from_secs(7),
            "explicit timer driver should override wall-clock default"
        );
        drop(guard);
    }

    #[test]
    fn runtime_builder_browser_worker_offload_policy_round_trips() {
        init_test_logging();

        let runtime = RuntimeBuilder::current_thread()
            .browser_worker_offload_enabled(true)
            .browser_worker_offload_limits(2048, 4)
            .browser_worker_transfer_mode(
                crate::runtime::config::WorkerTransferMode::CloneStructured,
            )
            .browser_worker_cancellation_mode(
                crate::runtime::config::WorkerCancellationMode::BestEffortAbort,
            )
            .build()
            .expect("runtime build");

        let offload = runtime.config().browser_worker_offload;
        assert!(offload.enabled, "offload policy should be enabled");
        assert_eq!(
            offload.min_task_cost, 2048,
            "min task cost should round-trip"
        );
        assert_eq!(
            offload.max_in_flight, 4,
            "in-flight limit should round-trip"
        );
        assert_eq!(
            offload.transfer_mode,
            crate::runtime::config::WorkerTransferMode::CloneStructured,
            "transfer mode should round-trip"
        );
        assert_eq!(
            offload.cancellation_mode,
            crate::runtime::config::WorkerCancellationMode::BestEffortAbort,
            "cancellation mode should round-trip"
        );
    }

    #[cfg(target_arch = "wasm32")]
    #[test]
    fn runtime_builder_fail_closes_browser_bootstrap_on_wasm() {
        let err = RuntimeBuilder::current_thread()
            .build()
            .expect_err("public browser bootstrap must fail closed on wasm");
        assert_eq!(
            err.kind(),
            crate::error::ErrorKind::ConfigError,
            "unsupported wasm browser bootstrap must surface as ConfigError"
        );
        let message = err.to_string();
        assert!(
            message.contains("browser bootstrap")
                && message.contains("RuntimeHostServices seam")
                && message.contains("threadless startup"),
            "error should explain why wasm browser bootstrap is still unsupported: {message}"
        );
    }

    #[derive(Debug, PartialEq, Eq)]
    struct TraceCounts {
        region_created: usize,
        spawn: usize,
        complete: usize,
        timer_scheduled: usize,
        timer_fired: usize,
        timer_cancelled: usize,
        io_requested: usize,
        io_ready: usize,
        cancel_request: usize,
    }

    fn parity_counts(events: Vec<TraceEvent>) -> TraceCounts {
        let mut counts = TraceCounts {
            region_created: 0,
            spawn: 0,
            complete: 0,
            timer_scheduled: 0,
            timer_fired: 0,
            timer_cancelled: 0,
            io_requested: 0,
            io_ready: 0,
            cancel_request: 0,
        };

        for event in events {
            match event.kind {
                TraceEventKind::RegionCreated => counts.region_created += 1,
                TraceEventKind::Spawn => counts.spawn += 1,
                TraceEventKind::Complete => counts.complete += 1,
                TraceEventKind::TimerScheduled => counts.timer_scheduled += 1,
                TraceEventKind::TimerFired => counts.timer_fired += 1,
                TraceEventKind::TimerCancelled => counts.timer_cancelled += 1,
                TraceEventKind::IoRequested => counts.io_requested += 1,
                TraceEventKind::IoReady => counts.io_ready += 1,
                TraceEventKind::CancelRequest => counts.cancel_request += 1,
                _ => {}
            }
        }

        counts
    }

    fn wait_for_runtime_quiescent(runtime: &Runtime) {
        for i in 0..2000 {
            let live_tasks = runtime
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .live_task_count();
            if live_tasks == 0 {
                return;
            }
            if i < 100 {
                std::thread::yield_now();
            } else {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        unreachable!("runtime failed to reach quiescence after waiting");
    }

    #[cfg(unix)]
    struct TestFdSource;

    #[cfg(unix)]
    impl std::os::fd::AsRawFd for TestFdSource {
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            0
        }
    }

    #[test]
    fn lab_runtime_matches_prod_trace_for_basic_spawn() {
        init_test_logging();

        let mut lab = LabRuntime::new(LabConfig::new(7).trace_capacity(1024));
        let lab_region = lab.state.create_root_region(Budget::INFINITE);
        for _ in 0..2 {
            let (task_id, mut handle) = lab
                .state
                .create_task(lab_region, Budget::INFINITE, async { 1_u8 })
                .expect("lab task spawn");
            lab.scheduler
                .lock()
                .schedule(task_id, Budget::INFINITE.priority);
            // Model the real block_on root that joins this child in the
            // production runtime, including its spawn and retirement.
            let (root_id, _root_handle) = lab
                .state
                .create_task(lab_region, Budget::INFINITE, async move {
                    let cx = Cx::current().expect("lab root context");
                    assert_eq!(handle.join(&cx).await.expect("lab child completes"), 1);
                })
                .expect("lab root spawn");
            lab.scheduler
                .lock()
                .schedule(root_id, Budget::INFINITE.priority);
            lab.run_until_quiescent();
        }

        let lab_counts = parity_counts(lab.trace().snapshot());
        assert_eq!(
            lab_counts.spawn, lab_counts.complete,
            "lab trace should complete every spawned task"
        );

        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("runtime build");
        for _ in 0..2 {
            let handle = runtime.handle().spawn(async { 1_u8 });
            let _ = runtime.block_on(handle);
        }
        wait_for_runtime_quiescent(&runtime);

        let runtime_counts = {
            let guard = runtime
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            parity_counts(guard.trace.snapshot())
        };
        assert_eq!(
            runtime_counts.spawn, runtime_counts.complete,
            "runtime trace should complete every spawned task"
        );

        assert_eq!(lab_counts, runtime_counts);
    }

    async fn sleep_once() {
        let now = Cx::current()
            .and_then(|cx| cx.timer_driver())
            .map_or(Time::from_nanos(1_000_000_000), |driver| driver.now());
        sleep(now, Duration::from_millis(1)).await;
    }

    #[test]
    fn runtime_block_on_drives_timer_sleep_without_reactor() {
        init_test_logging();

        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("runtime build");
        let started = Instant::now();

        runtime.block_on(async {
            let now = Cx::current()
                .and_then(|cx| cx.timer_driver())
                .expect("runtime block_on should install a timer driver")
                .now();
            sleep(now, Duration::from_millis(5)).await;
        });

        assert!(
            started.elapsed() < Duration::from_millis(200),
            "block_on timer sleep should not wait for the old 250ms idle poll floor"
        );

        let runtime_counts = {
            let guard = runtime
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            parity_counts(guard.trace.snapshot())
        };
        assert!(
            runtime_counts.timer_scheduled > 0,
            "runtime trace should record timer scheduling"
        );
        assert_eq!(
            runtime_counts.timer_scheduled, runtime_counts.timer_fired,
            "runtime trace should fire every scheduled timer"
        );
    }

    #[test]
    fn lab_runtime_matches_prod_trace_for_timer_sleep() {
        init_test_logging();

        let mut lab = LabRuntime::new(LabConfig::new(7).trace_capacity(1024));
        let lab_region = lab.state.create_root_region(Budget::INFINITE);
        let (task_id, mut handle) = lab
            .state
            .create_task(lab_region, Budget::INFINITE, sleep_once())
            .expect("lab sleep task spawn");
        lab.scheduler
            .lock()
            .schedule(task_id, Budget::INFINITE.priority);
        let (root_id, _root_handle) = lab
            .state
            .create_task(lab_region, Budget::INFINITE, async move {
                let cx = Cx::current().expect("lab root context");
                handle.join(&cx).await.expect("lab timer child completes");
            })
            .expect("lab root spawn");
        lab.scheduler
            .lock()
            .schedule(root_id, Budget::INFINITE.priority);

        // Either the joining root or its child can run first. Drain both
        // runnable tasks before advancing the clock so the child's timer is
        // registered at virtual time zero rather than after the advance.
        lab.run_until_idle();
        assert_eq!(lab.next_timer_deadline(), Some(Time::from_nanos(1_000_000)));
        lab.advance_time(1_000_000);
        lab.run_until_quiescent();

        let lab_counts = parity_counts(lab.trace().snapshot());
        assert!(
            lab_counts.timer_scheduled > 0,
            "lab trace should record timer scheduling"
        );
        assert_eq!(
            lab_counts.timer_scheduled, lab_counts.timer_fired,
            "lab trace should fire every scheduled timer"
        );

        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("runtime build");
        let handle = runtime.handle().spawn(sleep_once());
        runtime.block_on(handle);
        wait_for_runtime_quiescent(&runtime);

        let runtime_counts = {
            let guard = runtime
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            parity_counts(guard.trace.snapshot())
        };
        assert!(
            runtime_counts.timer_scheduled > 0,
            "runtime trace should record timer scheduling"
        );
        assert_eq!(
            runtime_counts.timer_scheduled, runtime_counts.timer_fired,
            "runtime trace should fire every scheduled timer"
        );

        assert_eq!(lab_counts, runtime_counts);
    }

    #[test]
    fn lab_runtime_matches_prod_trace_for_cancel_request() {
        init_test_logging();

        let mut lab = LabRuntime::new(LabConfig::new(7).trace_capacity(1024));
        let lab_region = lab.state.create_root_region(Budget::INFINITE);
        let _ = lab
            .state
            .create_task(lab_region, Budget::INFINITE, async {
                std::future::pending::<()>().await;
            })
            .expect("lab task spawn");
        let lab_cancel_effects =
            lab.state
                .cancel_request(lab_region, &CancelReason::user("stop"), None);
        let lab_counts = parity_counts(lab.trace().snapshot());
        let (tasks_to_schedule, lab_cancel_wakes) = lab_cancel_effects.into_parts();
        {
            let mut scheduler = lab.scheduler.lock();
            for (task_id, priority) in tasks_to_schedule {
                scheduler.schedule_cancel(task_id, priority);
            }
        }
        lab_cancel_wakes.dispatch();
        assert!(
            lab_counts.cancel_request > 0,
            "lab trace should record cancel request"
        );

        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("runtime build");
        let (runtime_cancel_effects, runtime_counts) = {
            let mut guard = runtime
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let region = runtime.inner.root_region;
            let _ = guard
                .create_task(region, Budget::INFINITE, async {
                    std::future::pending::<()>().await;
                })
                .expect("runtime task spawn");
            let effects = guard.cancel_request(region, &CancelReason::user("stop"), None);
            let counts = parity_counts(guard.trace.snapshot());
            (effects, counts)
        };
        let (tasks_to_schedule, runtime_cancel_wakes) = runtime_cancel_effects.into_parts();
        for (task_id, priority) in tasks_to_schedule {
            runtime.inner.scheduler.inject_cancel(task_id, priority);
        }
        runtime_cancel_wakes.dispatch();
        assert!(
            runtime_counts.cancel_request > 0,
            "runtime trace should record cancel request"
        );

        assert_eq!(lab_counts, runtime_counts);
    }

    #[cfg(unix)]
    #[test]
    fn lab_runtime_matches_prod_trace_for_io_ready() {
        init_test_logging();

        let mut lab = LabRuntime::new(LabConfig::new(7).trace_capacity(1024));
        let handle = lab.state.io_driver_handle().expect("lab io driver");
        let registration = handle
            .register(&TestFdSource, Interest::READABLE, noop_waker())
            .expect("lab register source");
        let io_key = registration.token();
        lab.lab_reactor()
            .inject_event(io_key, Event::readable(io_key), Duration::ZERO);
        lab.step_for_test();
        let lab_counts = parity_counts(lab.trace().snapshot());
        assert!(
            lab_counts.io_requested > 0,
            "lab trace should record io requested"
        );
        assert_eq!(
            lab_counts.io_requested, lab_counts.io_ready,
            "lab trace should record ready after request"
        );

        let reactor = Arc::new(LabReactor::new());
        let reactor_handle: Arc<dyn Reactor> = reactor.clone();
        let state = RuntimeState::with_reactor(reactor_handle);
        let driver = state.io_driver_handle().expect("runtime state io driver");
        let registration = driver
            .register(&TestFdSource, Interest::READABLE, noop_waker())
            .expect("runtime state register source");
        let io_key = registration.token();
        reactor.inject_event(io_key, Event::readable(io_key), Duration::ZERO);
        let trace = state.trace_handle();
        let now = Time::from_nanos(1_000_000_000);
        let mut seen = HashSet::new();
        let _ = driver.turn_with(Some(Duration::ZERO), |event, interest| {
            let io_key = event.token.0 as u64;
            let interest_bits = interest.unwrap_or(event.ready).bits();
            if seen.insert(io_key) {
                trace.record_event(|seq| TraceEvent::io_requested(seq, now, io_key, interest_bits));
            }
            trace.record_event(|seq| TraceEvent::io_ready(seq, now, io_key, event.ready.bits()));
        });

        let runtime_counts = parity_counts(state.trace.snapshot());
        assert!(
            runtime_counts.io_requested > 0,
            "runtime trace should record io requested"
        );
        assert_eq!(
            runtime_counts.io_requested, runtime_counts.io_ready,
            "runtime trace should record ready after request"
        );

        assert_eq!(lab_counts.io_requested, runtime_counts.io_requested);
        assert_eq!(lab_counts.io_ready, runtime_counts.io_ready);
    }

    fn with_clean_env<F, R>(f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let _guard = crate::test_utils::env_lock();
        clean_env_locked();
        f()
    }

    /// Helper: set env vars for a closure, then clean up.
    fn with_envs<F, R>(vars: &[(&str, &str)], f: F) -> R
    where
        F: FnOnce() -> R,
    {
        with_clean_env(|| {
            for (k, v) in vars {
                // SAFETY: test helpers guard environment mutation with env_lock.
                unsafe { std::env::set_var(k, v) };
            }
            let result = f();
            for (k, _) in vars {
                // SAFETY: test helpers guard environment mutation with env_lock.
                unsafe { std::env::remove_var(k) };
            }
            result
        })
    }

    fn clean_env_locked() {
        use crate::runtime::env_config::*;
        for var in &[
            ENV_WORKER_THREADS,
            ENV_TASK_QUEUE_DEPTH,
            ENV_THREAD_STACK_SIZE,
            ENV_THREAD_NAME_PREFIX,
            ENV_STEAL_BATCH_SIZE,
            ENV_CANCEL_LANE_MAX_STREAK,
            ENV_ENABLE_GOVERNOR,
            ENV_GOVERNOR_INTERVAL,
            ENV_ENABLE_ADAPTIVE_CANCEL_STREAK,
            ENV_ADAPTIVE_CANCEL_EPOCH_STEPS,
            ENV_BLOCKING_MIN_THREADS,
            ENV_BLOCKING_MAX_THREADS,
            ENV_ENABLE_PARKING,
            ENV_POLL_BUDGET,
        ] {
            // SAFETY: test helpers guard environment mutation with env_lock.
            unsafe { std::env::remove_var(var) };
        }
    }

    #[test]
    fn with_env_overrides_applies_env_vars() {
        use crate::runtime::env_config::*;
        with_envs(
            &[(ENV_WORKER_THREADS, "4"), (ENV_POLL_BUDGET, "64")],
            || {
                let runtime = RuntimeBuilder::new()
                    .with_env_overrides()
                    .expect("env overrides")
                    .build()
                    .expect("runtime build");
                assert_eq!(runtime.config().worker_threads, 4);
                assert_eq!(runtime.config().poll_budget, 64);
            },
        );
    }

    #[test]
    fn programmatic_overrides_env_vars() {
        use crate::runtime::env_config::*;
        with_envs(&[(ENV_WORKER_THREADS, "8")], || {
            // Env says 8, but programmatic says 2 — programmatic wins.
            let runtime = RuntimeBuilder::new()
                .with_env_overrides()
                .expect("env overrides")
                .worker_threads(2)
                .build()
                .expect("runtime build");
            assert_eq!(runtime.config().worker_threads, 2);
        });
    }

    #[test]
    fn with_env_overrides_invalid_var_returns_error() {
        use crate::runtime::env_config::*;
        with_envs(&[(ENV_WORKER_THREADS, "not_a_number")], || {
            let result = RuntimeBuilder::new().with_env_overrides();
            assert!(result.is_err());
        });
    }

    #[test]
    fn with_env_overrides_no_vars_uses_defaults() {
        with_clean_env(|| {
            let defaults = RuntimeConfig::default();
            let runtime = RuntimeBuilder::new()
                .with_env_overrides()
                .expect("env overrides")
                .build()
                .expect("runtime build");
            assert_eq!(
                runtime.config().cancel_lane_max_streak,
                defaults.cancel_lane_max_streak
            );
            assert_eq!(runtime.config().enable_governor, defaults.enable_governor);
            assert_eq!(
                runtime.config().governor_interval,
                defaults.governor_interval
            );
            assert_eq!(
                runtime.config().enable_read_biased_region_snapshot,
                defaults.enable_read_biased_region_snapshot
            );
            assert_eq!(
                runtime.config().enable_adaptive_cancel_streak,
                defaults.enable_adaptive_cancel_streak
            );
            assert_eq!(
                runtime.config().adaptive_cancel_streak_epoch_steps,
                defaults.adaptive_cancel_streak_epoch_steps
            );
            assert_eq!(runtime.config().poll_budget, defaults.poll_budget);
        });
    }

    #[test]
    fn with_env_overrides_applies_governor_settings() {
        use crate::runtime::env_config::*;
        with_envs(
            &[(ENV_ENABLE_GOVERNOR, "true"), (ENV_GOVERNOR_INTERVAL, "41")],
            || {
                let runtime = RuntimeBuilder::new()
                    .with_env_overrides()
                    .expect("env overrides")
                    .build()
                    .expect("runtime build");
                assert!(runtime.config().enable_governor);
                assert_eq!(runtime.config().governor_interval, 41);
            },
        );
    }

    #[cfg(feature = "config-file")]
    #[test]
    fn from_toml_str_builds_runtime() {
        let toml = r"
[scheduler]
worker_threads = 2
poll_budget = 32
";
        let runtime = RuntimeBuilder::from_toml_str(toml)
            .expect("from_toml_str")
            .build()
            .expect("runtime build");
        assert_eq!(runtime.config().worker_threads, 2);
        assert_eq!(runtime.config().poll_budget, 32);
    }

    #[cfg(feature = "config-file")]
    #[test]
    fn from_toml_str_applies_governor_settings() {
        let toml = r"
[scheduler]
enable_governor = true
governor_interval = 80
";
        let runtime = RuntimeBuilder::from_toml_str(toml)
            .expect("from_toml_str")
            .build()
            .expect("runtime build");
        assert!(runtime.config().enable_governor);
        assert_eq!(runtime.config().governor_interval, 80);
    }

    // asupersync-7yq1pv item 2: the builder gives its sink to every worker.
    fn run_with_scheduler_evidence_sink(enable_governor: bool) -> Vec<String> {
        use crate::evidence_sink::CollectorSink;

        init_test_logging();
        let sink = Arc::new(CollectorSink::new());
        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .enable_governor(enable_governor)
            .scheduler_evidence_sink(sink.clone())
            .build()
            .expect("runtime build");
        let handle = runtime.handle();
        let total = runtime.block_on(async move {
            let mut total = 0u32;
            for i in 0..8u32 {
                total += handle.spawn(async move { i }).await;
            }
            total
        });
        assert_eq!(total, 28);
        drop(runtime);
        sink.entries()
            .into_iter()
            .map(|entry| entry.component)
            .collect()
    }

    #[test]
    fn scheduler_evidence_sink_records_governor_decisions() {
        let components = run_with_scheduler_evidence_sink(true);
        assert!(
            !components.is_empty(),
            "no scheduling decision was recorded"
        );
        assert!(
            components.iter().any(|component| component == "scheduler"),
            "{components:?}"
        );
    }

    #[test]
    fn scheduler_evidence_sink_records_nothing_without_the_governor() {
        let components = run_with_scheduler_evidence_sink(false);
        assert!(components.is_empty(), "{components:?}");
    }

    #[cfg(feature = "config-file")]
    #[test]
    fn from_toml_str_with_programmatic_override() {
        let toml = r"
[scheduler]
worker_threads = 8
";
        let runtime = RuntimeBuilder::from_toml_str(toml)
            .expect("from_toml_str")
            .worker_threads(2) // programmatic override
            .build()
            .expect("runtime build");
        assert_eq!(runtime.config().worker_threads, 2);
    }

    #[cfg(feature = "config-file")]
    #[test]
    fn from_toml_str_invalid_returns_error() {
        let result = RuntimeBuilder::from_toml_str("not valid {{{{");
        assert!(result.is_err());
    }

    #[cfg(feature = "config-file")]
    #[test]
    fn from_json_str_builds_runtime_through_the_shared_typed_layer() {
        let json = r#"{
            "schema_version": 1,
            "config": {
                "scheduler": {
                    "worker_threads": 2,
                    "poll_budget": 32
                }
            }
        }"#;
        let runtime = RuntimeBuilder::from_json_str(json)
            .expect("from_json_str")
            .build()
            .expect("runtime build");
        assert_eq!(runtime.config().worker_threads, 2);
        assert_eq!(runtime.config().poll_budget, 32);
    }

    #[cfg(feature = "config-file")]
    #[test]
    fn from_json_str_rejects_unsupported_schema_version() {
        let result = RuntimeBuilder::from_json_str(
            r#"{"schema_version":2,"config":{"scheduler":{"worker_threads":2}}}"#,
        );
        let error = match result {
            Ok(_) => panic!("unsupported JSON schema must fail closed"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("schema version 2"));
    }

    #[cfg(feature = "config-file")]
    #[test]
    fn precedence_programmatic_over_env_over_json() {
        use crate::runtime::env_config::*;
        with_envs(&[(ENV_WORKER_THREADS, "8")], || {
            let json = r#"{
                "schema_version": 1,
                "config": {"scheduler": {"worker_threads": 16}}
            }"#;
            let runtime = RuntimeBuilder::from_json_str(json)
                .expect("from_json_str")
                .with_env_overrides()
                .expect("env overrides")
                .worker_threads(2)
                .build()
                .expect("runtime build");
            assert_eq!(runtime.config().worker_threads, 2);
        });
    }

    #[cfg(feature = "config-file")]
    #[test]
    fn precedence_programmatic_over_env_over_toml() {
        use crate::runtime::env_config::*;
        // TOML says 16, env says 8, programmatic says 2.
        with_envs(&[(ENV_WORKER_THREADS, "8")], || {
            let toml = r"
[scheduler]
worker_threads = 16
";
            let runtime = RuntimeBuilder::from_toml_str(toml)
                .expect("from_toml_str")
                .with_env_overrides()
                .expect("env overrides")
                .worker_threads(2) // programmatic: highest priority
                .build()
                .expect("runtime build");
            assert_eq!(runtime.config().worker_threads, 2);
        });
    }

    #[cfg(feature = "config-file")]
    #[test]
    fn precedence_env_over_toml() {
        use crate::runtime::env_config::*;
        // TOML says 16, env says 8.
        with_envs(&[(ENV_WORKER_THREADS, "8")], || {
            let toml = r"
[scheduler]
worker_threads = 16
";
            let runtime = RuntimeBuilder::from_toml_str(toml)
                .expect("from_toml_str")
                .with_env_overrides()
                .expect("env overrides")
                .build()
                .expect("runtime build");
            assert_eq!(runtime.config().worker_threads, 8);
        });
    }

    // -----------------------------------------------------------------------
    // Issue #21: Thread-local RuntimeHandle from block_on
    // -----------------------------------------------------------------------

    #[test]
    fn current_handle_available_inside_block_on() {
        init_test_logging();
        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .build()
            .expect("runtime build");

        runtime.block_on(async {
            let handle = Runtime::current_handle();
            assert!(
                handle.is_some(),
                "current_handle should be Some inside block_on"
            );
        });
    }

    #[test]
    fn current_handle_none_outside_block_on() {
        init_test_logging();
        assert!(
            Runtime::current_handle().is_none(),
            "current_handle should be None outside block_on"
        );
    }

    #[test]
    fn enable_time_installs_wall_clock_driver() {
        // br-asupersync-runtime-cpu-overhaul-5vt09v.3.1: enable_time() is the
        // discoverable opt-in that installs a wall-clock timer driver so a
        // consumer cannot forget it (and so the off-driver Sleep fallback warn
        // never has to fire). A fresh builder has no driver; enable_time()
        // installs one.
        init_test_logging();
        let builder = RuntimeBuilder::new();
        assert!(
            builder.timer_driver.is_none(),
            "fresh builder has no timer driver"
        );
        let builder = builder.enable_time();
        assert!(
            builder.timer_driver.is_some(),
            "enable_time installs a wall-clock timer driver"
        );
    }

    #[test]
    fn enable_time_does_not_clobber_explicit_driver() {
        // enable_time() must compose with with_timer_driver() in any order
        // without overwriting an explicitly-provided driver
        // (br-asupersync-runtime-cpu-overhaul-5vt09v.3.1).
        init_test_logging();
        let explicit = TimerDriverHandle::with_wall_clock();
        let builder = RuntimeBuilder::new()
            .with_timer_driver(explicit.clone())
            .enable_time();
        assert!(
            builder
                .timer_driver
                .as_ref()
                .is_some_and(|d| d.ptr_eq(&explicit)),
            "enable_time must preserve an explicitly-provided driver"
        );
    }

    #[test]
    fn current_handle_spawn_completes_on_scheduler() {
        init_test_logging();
        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .build()
            .expect("runtime build");

        let flag = Arc::new(AtomicBool::new(false));
        let flag_clone = Arc::clone(&flag);

        let result = runtime.block_on(async move {
            let handle = Runtime::current_handle().expect("inside block_on");
            let join = handle.spawn(async move {
                flag_clone.store(true, Ordering::SeqCst);
                99u32
            });
            join.await
        });

        assert_eq!(result, 99);
        assert!(flag.load(Ordering::SeqCst), "spawned task should have run");
    }

    #[test]
    fn current_handle_available_inside_spawned_task() {
        init_test_logging();
        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .build()
            .expect("runtime build");

        let outer = runtime.handle().spawn(async {
            let handle = Runtime::current_handle().expect("spawned task should see runtime handle");
            handle.spawn(async { 42u32 }).await
        });

        assert_eq!(runtime.block_on(outer), 42);
    }

    #[test]
    fn runtime_handle_request_cx_preserves_budget_and_runtime_authority() {
        init_test_logging();
        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .enable_time()
            .build()
            .expect("runtime build");
        let budget = Budget::new().with_poll_quota(37).with_cost_quota(91);

        let runtime_cx = runtime.request_cx_with_budget(budget);
        let handle_cx = runtime.handle().request_cx_with_budget(budget);

        assert_eq!(handle_cx.budget(), budget);
        assert_eq!(handle_cx.region_id(), runtime_cx.region_id());
        assert_eq!(
            handle_cx.io_driver_handle().is_some(),
            runtime_cx.io_driver_handle().is_some(),
            "handle-minted contexts must preserve runtime IO authority"
        );
        assert_eq!(
            handle_cx.timer_driver().is_some(),
            runtime_cx.timer_driver().is_some(),
            "handle-minted contexts must preserve runtime time authority"
        );
        assert!(
            handle_cx.spawn_gateway_handle().is_some(),
            "handle-minted contexts must carry the runtime spawn gateway"
        );
        assert!(
            handle_cx.pending_spawn_counter_handle().is_some(),
            "handle-minted contexts must carry root pending-spawn accounting"
        );

        let mut child = handle_cx
            .spawn(|child_cx| async move {
                child_cx.checkpoint().expect("child checkpoint");
                42_u8
            })
            .expect("handle-minted Cx must spawn through the runtime gateway");
        let joined = runtime.block_on(async { child.join(&handle_cx).await });
        assert_eq!(joined.expect("spawned child joins"), 42);
    }

    #[test]
    fn current_handle_restored_after_block_on() {
        init_test_logging();
        // Before block_on: None.
        assert!(Runtime::current_handle().is_none());

        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .build()
            .expect("runtime build");

        runtime.block_on(async {
            assert!(Runtime::current_handle().is_some());
        });

        // After block_on: restored to None.
        assert!(Runtime::current_handle().is_none());
    }

    /// br-asupersync-1ajbtl: the default platform reactor attaches a real
    /// IoDriver, so spawned tasks see an io-driver handle through their Cx
    /// and socket I/O uses reactor readiness instead of fallback re-polls.
    #[test]
    fn default_build_attaches_platform_io_driver() {
        init_test_logging();
        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .build()
            .expect("runtime build");
        let has_driver = runtime.block_on(runtime.handle().spawn(async {
            crate::cx::Cx::current()
                .expect("spawned task has a Cx")
                .io_driver_handle()
                .is_some()
        }));
        assert!(has_driver, "default runtime builds must attach an IoDriver");
        assert_ne!(
            runtime.io_reactor_capability_snapshot().backend(),
            crate::runtime::reactor::IoReactorBackend::Unavailable
        );
    }

    /// Pins the explicit fallback regime: callers may still disable the
    /// platform reactor when isolating platform bring-up issues.
    #[test]
    fn disabled_platform_reactor_attaches_no_io_driver() {
        init_test_logging();
        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .enable_platform_reactor(false)
            .build()
            .expect("runtime build");
        let has_driver = runtime.block_on(runtime.handle().spawn(async {
            crate::cx::Cx::current()
                .expect("spawned task has a Cx")
                .io_driver_handle()
                .is_some()
        }));
        assert!(
            !has_driver,
            "explicitly disabled platform reactor must keep fallback I/O regime"
        );
        let snapshot = runtime.io_reactor_capability_snapshot();
        assert_eq!(
            snapshot.backend(),
            crate::runtime::reactor::IoReactorBackend::Unavailable
        );
        assert_eq!(snapshot.selection_fallback(), None);
    }

    #[test]
    fn terminal_platform_reactor_snapshot_survives_without_io_driver() {
        use crate::runtime::reactor::{
            IoReactorBackend, IoUringCapability, IoUringFallbackReason, IoUringSupportState,
        };

        let policy =
            IoUringCapabilityPolicy::new().with_requested(IoUringCapability::FixedBuffers, true);
        let expected = IoReactorCapabilitySnapshot::reactor_unavailable(policy);
        let runtime = Runtime::with_config_and_platform_snapshot(
            RuntimeConfig::default(),
            None,
            None,
            None,
            None,
            Some(expected),
            &NativeThreadHostServices::new(),
            false,
            None,
            None,
            BlockingQueuePolicy::Fifo,
        )
        .expect("runtime construction continues without a reactor");

        let state = runtime
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(state.io_driver_handle().is_none());
        drop(state);

        let snapshot = runtime.io_reactor_capability_snapshot();
        assert_eq!(snapshot, expected);
        assert_eq!(snapshot.backend(), IoReactorBackend::Unavailable);
        assert_eq!(
            snapshot.selection_fallback(),
            Some(IoUringFallbackReason::ReactorUnavailable)
        );
        let fixed = snapshot.decision(IoUringCapability::FixedBuffers);
        assert_eq!(fixed.supported(), IoUringSupportState::NotProbed);
        assert!(!fixed.active());
        assert_eq!(
            fixed.fallback_reason(),
            IoUringFallbackReason::ReactorUnavailable
        );
        assert_eq!(
            runtime.handle().io_reactor_capability_snapshot(),
            Some(expected)
        );
    }

    #[test]
    fn io_uring_capability_force_off_is_immutable_and_host_independent() {
        use crate::runtime::reactor::{
            IoUringCapability, IoUringFallbackReason, IoUringSupportState,
        };

        let policy = IoUringCapabilityPolicy::new()
            .with_requested(IoUringCapability::FixedBuffers, true)
            .with_forced_off(IoUringCapability::FixedBuffers, true);
        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .io_uring_capability_policy(policy)
            .build()
            .expect("runtime build");

        let snapshot = runtime
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .io_driver_handle()
            .expect("default platform driver")
            .capability_snapshot();
        let forced = snapshot.decision(IoUringCapability::FixedBuffers);
        assert!(forced.requested());
        assert_eq!(forced.supported(), IoUringSupportState::NotProbed);
        assert!(!forced.active());
        assert_eq!(forced.fallback_reason(), IoUringFallbackReason::ForcedOff);

        let unrequested = snapshot.decision(IoUringCapability::MultishotAccept);
        assert!(!unrequested.requested());
        assert_eq!(
            unrequested.fallback_reason(),
            IoUringFallbackReason::NotRequested
        );
    }

    #[test]
    fn current_handle_returns_none_during_thread_local_teardown() {
        init_test_logging();
        CURRENT_HANDLE_DTOR_STATE.store(0, Ordering::SeqCst);

        let join = std::thread::spawn(|| {
            // Initialize the probe first so its destructor runs after the
            // runtime handle TLS and can exercise the teardown path.
            CURRENT_HANDLE_DTOR_PROBE.with(|_| {});

            let runtime = RuntimeBuilder::current_thread()
                .build()
                .expect("runtime build");
            runtime.block_on(async {
                assert!(
                    Runtime::current_handle().is_some(),
                    "runtime handle should be installed inside block_on"
                );
            });
        });

        join.join()
            .expect("thread-local teardown should not panic when reading runtime handle");
        assert_eq!(
            CURRENT_HANDLE_DTOR_STATE.load(Ordering::SeqCst),
            3,
            "Runtime::current_handle() should fail closed once TLS is unavailable"
        );
    }

    #[test]
    fn weak_current_handle_try_spawn_returns_runtime_unavailable_after_drop() {
        init_test_logging();
        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .build()
            .expect("runtime build");

        let weak_handle = runtime.block_on(runtime.handle().spawn(async {
            Runtime::current_handle().expect("spawned task should see runtime handle")
        }));
        assert!(
            matches!(weak_handle.inner, RuntimeHandleRef::Weak(_)),
            "worker-thread current_handle should remain weak to avoid runtime cycles"
        );
        let certificates = weak_handle
            .preemption_fairness_certificates()
            .expect("worker-installed weak handle upgrades while runtime is alive");
        assert_eq!(certificates.len(), 1);
        assert!(
            certificates
                .iter()
                .all(|certificate| certificate.invariant_holds())
        );

        drop(runtime);

        assert_eq!(weak_handle.preemption_fairness_certificates(), None);
        let result = weak_handle.try_spawn(async { 42u8 });
        assert!(
            matches!(result, Err(SpawnError::RuntimeUnavailable)),
            "stale weak handle should return RuntimeUnavailable instead of panicking"
        );
        assert!(
            matches!(
                weak_handle.try_request_cx_with_budget(Budget::INFINITE),
                Err(SpawnError::RuntimeUnavailable)
            ),
            "stale weak handle should fail request-Cx creation without manufacturing authority"
        );
        assert!(
            weak_handle.spawn_blocking(|| {}).is_none(),
            "stale weak handle should not expose a blocking pool"
        );
        assert!(
            weak_handle.blocking_handle().is_none(),
            "stale weak handle should not yield a blocking handle"
        );
    }

    /// The ambient Cx installed by `Runtime::block_on` must carry the spawn
    /// gateway and the root region's pending-spawn counter, so `Cx::spawn`
    /// works from the `#[asupersync::main]` body (br-asupersync-zc5865).
    /// Before the fix this failed with `SpawnError::RuntimeUnavailable`
    /// while the runtime's workers sat idle.
    #[test]
    fn block_on_ambient_cx_spawns_through_the_gateway() {
        init_test_logging();
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("runtime build");
        let joined = runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs an ambient Cx");
            assert!(
                cx.spawn_gateway_handle().is_some(),
                "ambient Cx must carry the spawn gateway (br-asupersync-zc5865)"
            );
            assert!(
                cx.pending_spawn_counter_handle().is_some(),
                "ambient Cx must carry the root region's pending-spawn counter"
            );
            let mut handle = cx
                .spawn(|task_cx| async move {
                    task_cx.checkpoint().expect("child checkpoint");
                    41_u32 + 1
                })
                .expect("ambient Cx spawn must reach the gateway");
            handle.join(&cx).await.expect("spawned child joins")
        });
        assert_eq!(
            joined, 42,
            "the child spawned from the block_on body must run to completion"
        );
    }

    #[test]
    fn thread_callbacks_do_not_fire_for_block_on_caller() {
        init_test_logging();
        let started = Arc::new(AtomicUsize::new(0));
        let stopped = Arc::new(AtomicUsize::new(0));
        let started_for_callback = Arc::clone(&started);
        let stopped_for_callback = Arc::clone(&stopped);

        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .on_thread_start(move || {
                started_for_callback.fetch_add(1, Ordering::Relaxed);
            })
            .on_thread_stop(move || {
                stopped_for_callback.fetch_add(1, Ordering::Relaxed);
            })
            .build()
            .expect("runtime build");

        let join = runtime.handle().spawn(async { 7u8 });
        assert_eq!(runtime.block_on(join), 7);
        assert_eq!(
            started.load(Ordering::SeqCst),
            1,
            "only the worker thread should trigger on_thread_start"
        );

        drop(runtime);

        assert_eq!(
            stopped.load(Ordering::SeqCst),
            1,
            "only the worker thread should trigger on_thread_stop"
        );
    }

    #[test]
    fn join_handle_second_poll_panics_after_success_and_stays_finished() {
        init_test_logging();

        let state = Arc::new(Mutex::new(JoinState::new()));
        complete_task(&state, Ok(7_u8));

        let mut join = std::pin::pin!(JoinHandle::new(Arc::clone(&state)));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = join.as_mut().poll(&mut cx);
        assert!(matches!(first, Poll::Ready(7)));
        assert!(
            join.as_ref().get_ref().is_finished(),
            "join handle should remain finished after consuming the result"
        );

        let second = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = join.as_mut().poll(&mut cx);
        }));
        let message =
            panic_payload_to_string(second.expect_err("second poll must fail closed by panicking"));
        assert!(
            message.contains("runtime::JoinHandle polled after completion"),
            "second poll should panic with completion misuse message, got {message}"
        );
        assert!(
            join.as_ref().get_ref().is_finished(),
            "join handle should remain finished after post-completion misuse"
        );
    }

    #[test]
    fn join_handle_pending_then_completion_then_repoll_panics_and_stays_finished() {
        init_test_logging();

        let state = Arc::new(Mutex::new(JoinState::new()));
        let mut join = std::pin::pin!(JoinHandle::new(Arc::clone(&state)));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = join.as_mut().poll(&mut cx);
        assert!(matches!(first, Poll::Pending));
        assert!(
            !join.as_ref().get_ref().is_finished(),
            "join handle should not be finished while task is still pending"
        );

        complete_task(&state, Ok(11_u8));

        let second = join.as_mut().poll(&mut cx);
        assert!(matches!(second, Poll::Ready(11)));
        assert!(
            join.as_ref().get_ref().is_finished(),
            "join handle should become finished after ready output is observed"
        );

        let third = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = join.as_mut().poll(&mut cx);
        }));
        let message =
            panic_payload_to_string(third.expect_err("third poll must fail closed by panicking"));
        assert!(
            message.contains("runtime::JoinHandle polled after completion"),
            "post-completion repoll should panic with completion misuse message, got {message}"
        );
        assert!(
            join.as_ref().get_ref().is_finished(),
            "join handle should remain finished after post-completion misuse"
        );
    }

    #[test]
    fn join_handle_second_poll_panics_after_task_panic_and_stays_finished() {
        init_test_logging();

        let state = Arc::new(Mutex::new(JoinState::<u8>::new()));
        complete_task(&state, Err(Box::new("join-handle boom")));

        let mut join = std::pin::pin!(JoinHandle::new(Arc::clone(&state)));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = join.as_mut().poll(&mut cx);
        }));
        let first_message =
            panic_payload_to_string(first.expect_err("first poll should resume the task panic"));
        assert!(
            first_message.contains("join-handle boom"),
            "first poll should preserve the original task panic, got {first_message}"
        );
        assert!(
            join.as_ref().get_ref().is_finished(),
            "join handle should remain finished after propagating a task panic"
        );

        let second = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = join.as_mut().poll(&mut cx);
        }));
        let second_message =
            panic_payload_to_string(second.expect_err("second poll must fail closed by panicking"));
        assert!(
            second_message.contains("runtime::JoinHandle polled after completion"),
            "second poll should panic with completion misuse message, got {second_message}"
        );
        assert!(
            join.as_ref().get_ref().is_finished(),
            "join handle should remain finished after post-completion misuse"
        );
    }

    #[test]
    fn join_handle_is_finished_after_executor_side_disappears() {
        init_test_logging();

        let state = Arc::new(Mutex::new(JoinState::<u8>::new()));
        let mut join = std::pin::pin!(JoinHandle::new(Arc::clone(&state)));
        drop(state);

        assert!(
            join.as_ref().get_ref().is_finished(),
            "join handle should report terminal dropped-task state as finished"
        );

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let poll_after_drop = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = join.as_mut().poll(&mut cx);
        }));
        let message = panic_payload_to_string(
            poll_after_drop.expect_err("poll after executor-side disappearance must panic"),
        );
        assert!(
            message.contains("task was dropped or cancelled before completion"),
            "poll after executor-side disappearance should preserve dropped-task panic, got {message}"
        );
        assert!(
            join.as_ref().get_ref().is_finished(),
            "join handle should remain finished after the terminal dropped-task poll"
        );
    }

    #[test]
    fn checked_join_reports_runtime_shutdown_without_unwinding() {
        init_test_logging();

        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .build()
            .expect("runtime build");
        let runtime_handle = runtime.handle();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let join = runtime_handle.spawn_checked(async move {
            started_tx.send(()).expect("report task start");
            std::future::pending::<u8>().await
        });
        started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("task must reach its pending state before runtime shutdown");

        drop(runtime_handle);
        drop(runtime);

        let observer = RuntimeBuilder::current_thread()
            .build()
            .expect("observer runtime build");
        let result = observer.block_on(join);
        assert!(matches!(
            result,
            Err(crate::runtime::JoinError::Cancelled(CancelReason {
                kind: crate::types::CancelKind::Shutdown,
                ..
            }))
        ));
    }

    #[test]
    fn checked_join_reports_current_thread_shutdown_before_first_poll() {
        init_test_logging();

        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("runtime build");
        let join = runtime.handle().spawn_checked(std::future::pending::<u8>());
        drop(runtime);

        let observer = RuntimeBuilder::current_thread()
            .build()
            .expect("observer runtime build");
        assert!(matches!(
            observer.block_on(join),
            Err(crate::runtime::JoinError::Cancelled(CancelReason {
                kind: crate::types::CancelKind::Shutdown,
                ..
            }))
        ));
    }

    #[test]
    fn checked_join_pending_observer_is_woken_by_runtime_shutdown() {
        init_test_logging();

        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .build()
            .expect("runtime build");
        let runtime_handle = runtime.handle();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let mut join = Box::pin(runtime_handle.spawn_checked(async move {
            started_tx.send(()).expect("report task start");
            std::future::pending::<u8>().await
        }));
        started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("task must reach its pending state before runtime shutdown");

        let observer_waker = Arc::new(ThreadWaker {
            thread: std::thread::current(),
            woken: AtomicBool::new(false),
        });
        let waker = Waker::from(Arc::clone(&observer_waker));
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(join.as_mut().poll(&mut cx), Poll::Pending));
        assert!(!observer_waker.woken.load(Ordering::Acquire));

        drop(runtime_handle);
        drop(runtime);

        assert!(
            observer_waker.woken.load(Ordering::Acquire),
            "dropping the executor side must wake an already-pending checked join"
        );
        assert!(matches!(
            join.as_mut().poll(&mut cx),
            Poll::Ready(Err(crate::runtime::JoinError::Cancelled(CancelReason {
                kind: crate::types::CancelKind::Shutdown,
                ..
            })))
        ));
    }

    #[test]
    fn checked_join_types_unadmitted_cancellation_without_changing_legacy_payload() {
        init_test_logging();

        let reason = CancelReason::user("mailbox admission refused");
        let expected_legacy_payload = format!("spawn cancelled before admission: {reason}");

        let checked_state = Arc::new(Mutex::new(JoinState::<u8>::new()));
        JoinProducer::new(Arc::clone(&checked_state)).cancel(reason.clone());
        let mut checked = std::pin::pin!(CheckedJoinHandle::new(JoinHandle::new(checked_state)));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(
            checked.as_mut().poll(&mut cx),
            Poll::Ready(Err(crate::runtime::JoinError::Cancelled(actual))) if actual == reason
        ));

        let legacy_state = Arc::new(Mutex::new(JoinState::<u8>::new()));
        JoinProducer::new(Arc::clone(&legacy_state)).cancel(reason);
        let mut legacy = std::pin::pin!(JoinHandle::new(legacy_state));
        let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = legacy.as_mut().poll(&mut cx);
        }));
        assert_eq!(
            panic_payload_to_string(observed.expect_err("legacy join must retain its panic path")),
            expected_legacy_payload,
            "the additive checked API must not rewrite the v0.4.3 legacy panic payload"
        );
    }

    #[test]
    fn checked_join_preserves_task_panic_as_typed_error() {
        init_test_logging();

        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .build()
            .expect("runtime build");
        let join = runtime
            .handle()
            .spawn_checked(async { panic!("checked-join boom") });

        let result = runtime.block_on(join);
        match result {
            Err(crate::runtime::JoinError::Panicked(payload)) => assert_eq!(
                payload.message(),
                "checked-join boom",
                "typed checked join must retain the task panic message"
            ),
            other => panic!("task panic must be a typed checked-join error, got {other:?}"),
        }
    }

    #[test]
    fn checked_join_repoll_returns_polled_after_completion() {
        init_test_logging();

        let state = Arc::new(Mutex::new(JoinState::new()));
        complete_task(&state, Ok(17_u8));
        let mut join = std::pin::pin!(CheckedJoinHandle::new(JoinHandle::new(state)));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(join.as_mut().poll(&mut cx), Poll::Ready(Ok(17))));
        assert!(matches!(
            join.as_mut().poll(&mut cx),
            Poll::Ready(Err(crate::runtime::JoinError::PolledAfterCompletion))
        ));
    }

    #[test]
    fn checked_join_is_finished_when_cancellation_is_published() {
        let state = Arc::new(Mutex::new(JoinState::<u8>::new()));
        let executor_ref = Arc::clone(&state);
        lock_state(&state).cancel_reason = Some(CancelReason::shutdown());
        let join = CheckedJoinHandle::new(JoinHandle::new(state));

        assert!(
            join.is_finished(),
            "typed cancellation is terminal before the executor releases its final state ref"
        );
        drop(executor_ref);
    }

    /// br-asupersync-3lk5n2: a Runtime's `request_cx_with_budget`
    /// must mint successive request-scoped TaskIds from a per-runtime
    /// counter — NOT from the process-global `EPHEMERAL_TASK_COUNTER`.
    /// This test confirms intra-runtime monotonicity AND that two
    /// independently-built runtimes share the deterministic counter
    /// shape (each starts at 1) rather than racing on the global
    /// counter. Replay determinism follows.
    #[test]
    fn lk5n2_request_task_ids_are_deterministic_per_runtime() {
        init_test_logging();
        let rt_a = RuntimeBuilder::new().build().expect("build runtime A");
        let rt_b = RuntimeBuilder::new().build().expect("build runtime B");

        let a1 = rt_a.request_cx_with_budget(Budget::INFINITE).task_id();
        let a2 = rt_a.request_cx_with_budget(Budget::INFINITE).task_id();
        let b1 = rt_b.request_cx_with_budget(Budget::INFINITE).task_id();
        let b2 = rt_b.request_cx_with_budget(Budget::INFINITE).task_id();

        // Successive ids in the same runtime must increment.
        assert_ne!(
            a1, a2,
            "br-asupersync-3lk5n2: per-runtime counter must advance"
        );
        assert_ne!(
            b1, b2,
            "br-asupersync-3lk5n2: per-runtime counter must advance"
        );

        // Two runtimes must each start their own counter, so the
        // first-id-of-A and first-id-of-B match — they are NOT racing
        // on the process-global EPHEMERAL_TASK_COUNTER.
        assert_eq!(
            a1, b1,
            "br-asupersync-3lk5n2: each runtime starts its own counter; \
             this assertion would have failed when both shared the \
             process-global ephemeral counter"
        );
        assert_eq!(
            a2, b2,
            "br-asupersync-3lk5n2: per-runtime counters advance \
             identically — replay determinism"
        );

        // Drop the runtimes cleanly to avoid side effects on later tests.
        drop(rt_a);
        drop(rt_b);
    }

    /// AUDIT: Configuration validation approach - normalization vs rejection.
    ///
    /// This test pins the current behavior where invalid configurations are
    /// normalized to safe defaults rather than rejected with clear errors.
    /// The philosophy is defensive programming - fix invalid inputs rather
    /// than crashing. However, this may mask misconfigurations.
    #[test]
    fn audit_configuration_validation_normalizes_invalid_inputs() {
        init_test_logging();

        // Test zero worker threads - should be normalized to 1
        let runtime = RuntimeBuilder::new()
            .worker_threads(0)
            .build()
            .expect("zero worker_threads should be normalized, not rejected");

        // Verify the runtime was built successfully despite invalid input
        assert!(
            runtime.inner.config.worker_threads > 0,
            "worker_threads should be normalized from 0 to positive value"
        );
        drop(runtime);

        // Test other zero values that should be normalized
        let mut config = crate::runtime::config::RuntimeConfig::default();
        config.worker_threads = 0;
        config.poll_budget = 0;
        config.steal_batch_size = 0;
        config.cancel_lane_max_streak = 0;
        config.governor_interval = 0;
        config.thread_stack_size = 0;

        config.normalize();

        assert_eq!(
            config.worker_threads, 1,
            "zero worker_threads normalized to 1"
        );
        assert_eq!(config.poll_budget, 1, "zero poll_budget normalized to 1");
        assert_eq!(
            config.steal_batch_size, 1,
            "zero steal_batch_size normalized to 1"
        );
        assert_eq!(
            config.cancel_lane_max_streak, 1,
            "zero cancel_lane_max_streak normalized to 1"
        );
        assert_eq!(
            config.governor_interval, 1,
            "zero governor_interval normalized to 1"
        );
        assert_eq!(
            config.thread_stack_size,
            2 * 1024 * 1024,
            "zero thread_stack_size normalized to 2MB"
        );

        // Verify normalization itself does not clamp extreme worker counts.
        // Do not build a runtime here: building would try to spawn that many
        // workers, which tests the host rather than the configuration layer.
        let mut extreme_config = crate::runtime::config::RuntimeConfig::default();
        extreme_config.worker_threads = usize::MAX;
        extreme_config.normalize();
        assert_eq!(
            extreme_config.worker_threads,
            usize::MAX,
            "extreme worker_threads value should be accepted as-is"
        );

        // FINDING: RuntimeBuilder follows normalization approach, not validation.
        // - Zero values are silently corrected to safe defaults
        // - Config normalization accepts extreme values without bounds checking
        // - No ConfigurationError is returned for invalid combinations
        //
        // This is SOUND behavior for defensive programming, but may mask
        // genuine misconfigurations. Alternative would be strict validation
        // with clear error messages for invalid inputs.
    }

    #[test]
    fn runtime_builder_expected_concurrent_tasks_sets_explicit_capacity_hints() {
        init_test_logging();

        let builder = RuntimeBuilder::new().expected_concurrent_tasks(4096);

        assert_eq!(
            builder.config.capacity_hints,
            Some(RuntimeCapacityHints::from_expected_concurrent_tasks(4096))
        );
    }

    #[test]
    fn runtime_builder_worker_cohorts_sets_explicit_mapping() {
        init_test_logging();

        let builder = RuntimeBuilder::new()
            .worker_threads(4)
            .worker_cohorts(vec![0, 0, 1, 1]);

        assert_eq!(
            builder.config.worker_cohort_map,
            Some(WorkerCohortMapping::new(vec![0, 0, 1, 1]))
        );
    }

    #[test]
    fn runtime_builder_scheduler_placement_mode_sets_explicit_policy() {
        init_test_logging();

        let builder =
            RuntimeBuilder::new().scheduler_placement_mode(SchedulerPlacementMode::ThroughputFirst);

        assert_eq!(
            builder.config.scheduler_placement_mode,
            SchedulerPlacementMode::ThroughputFirst
        );
    }

    #[test]
    fn runtime_builder_rejects_mismatched_worker_cohort_map() {
        init_test_logging();

        let err = match RuntimeBuilder::new()
            .worker_threads(4)
            .worker_cohorts(vec![0, 1])
            .build()
        {
            Err(err) => err,
            Ok(_) => panic!("mismatched cohort map should fail closed"),
        };

        assert_eq!(err.kind(), crate::error::ErrorKind::ConfigError);
        assert!(
            err.to_string()
                .contains("worker cohort map length must match worker_threads"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn runtime_builder_build_preserves_worker_cohort_map() {
        init_test_logging();

        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .worker_cohorts(vec![0, 1])
            .build()
            .expect("matching cohort map should build");

        assert_eq!(
            runtime.config().worker_cohort_map,
            Some(WorkerCohortMapping::new(vec![0, 1]))
        );
    }

    #[test]
    fn runtime_builder_build_preserves_scheduler_placement_mode() {
        init_test_logging();

        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .worker_cohorts(vec![0, 1])
            .scheduler_placement_mode(SchedulerPlacementMode::LatencyFirst)
            .build()
            .expect("matching cohort map should build");

        assert_eq!(
            runtime.config().scheduler_placement_mode,
            SchedulerPlacementMode::LatencyFirst
        );
    }

    #[test]
    fn runtime_builder_blocking_affinity_profile_sets_explicit_profile() {
        init_test_logging();

        let builder = RuntimeBuilder::new().blocking_affinity_profile(
            crate::runtime::config::BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit: 8,
                spill_check_interval: 2,
            },
        );

        assert_eq!(
            builder.config.blocking.affinity_profile,
            crate::runtime::config::BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit: 8,
                spill_check_interval: 2,
            }
        );
    }

    #[test]
    fn runtime_builder_build_preserves_blocking_affinity_profile() {
        init_test_logging();

        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .worker_cohorts(vec![0, 1])
            .blocking_threads(1, 2)
            .blocking_affinity_profile(
                crate::runtime::config::BlockingPoolAffinityProfile::CohortBiased {
                    local_queue_soft_limit: 4,
                    spill_check_interval: 1,
                },
            )
            .build()
            .expect("cohort-aware blocking profile should build");

        assert_eq!(
            runtime.config().blocking.affinity_profile,
            crate::runtime::config::BlockingPoolAffinityProfile::CohortBiased {
                local_queue_soft_limit: 4,
                spill_check_interval: 1,
            }
        );
    }

    #[test]
    fn runtime_builder_preserves_arena_temperature_policy() {
        init_test_logging();

        let builder = RuntimeBuilder::new().arena_temperature_policy(
            crate::runtime::config::ArenaTemperaturePolicy::TieredColdEvidenceLargePages,
        );

        assert_eq!(
            builder.config.arena_temperature_policy,
            crate::runtime::config::ArenaTemperaturePolicy::TieredColdEvidenceLargePages,
        );
    }

    #[test]
    fn initialize_runtime_state_auto_scales_capacities_from_worker_threads() {
        init_test_logging();

        let config = RuntimeConfig {
            worker_threads: 64,
            ..RuntimeConfig::default()
        };
        let state = RuntimeInner::initialize_runtime_state(&config, None, None, None, None, None);

        assert_eq!(
            state.capacity_hints(),
            RuntimeCapacityHints::for_worker_threads(64),
            "worker-scaled defaults should widen the initial arena sizes on high-core runtimes"
        );
    }

    #[test]
    fn initialize_runtime_state_respects_explicit_capacity_hints() {
        init_test_logging();

        let config = RuntimeConfig {
            capacity_hints: Some(RuntimeCapacityHints::new(4096, 1024, 2048)),
            ..RuntimeConfig::default()
        };
        let state = RuntimeInner::initialize_runtime_state(&config, None, None, None, None, None);

        assert_eq!(
            state.capacity_hints(),
            RuntimeCapacityHints::new(4096, 1024, 2048),
            "explicit runtime capacity hints should flow into the live runtime state"
        );
    }

    #[test]
    fn initialize_runtime_state_applies_read_biased_region_snapshot_gate() {
        init_test_logging();

        let config = RuntimeConfig {
            enable_read_biased_region_snapshot: true,
            ..RuntimeConfig::default()
        };
        let state = RuntimeInner::initialize_runtime_state(&config, None, None, None, None, None);

        assert!(
            state.read_biased_region_snapshot_enabled(),
            "builder config should enable the cached draining-region snapshot path"
        );
    }

    #[test]
    fn runtime_state_shape_defaults_to_unified() {
        init_test_logging();

        let config = RuntimeConfig::default();
        assert_eq!(
            config.runtime_state_shape,
            crate::runtime::config::RuntimeStateShape::Unified,
            "br-asupersync-8fuxnt: default backing-state shape must remain \
             Unified to preserve all pre-bead behavior"
        );
    }

    #[test]
    fn with_sharded_state_setter_flips_shape_in_config() {
        init_test_logging();

        let builder_unified = RuntimeBuilder::new();
        assert_eq!(
            builder_unified.config.runtime_state_shape,
            crate::runtime::config::RuntimeStateShape::Unified,
            "fresh RuntimeBuilder must start in Unified shape"
        );

        let builder_sharded = RuntimeBuilder::new().with_sharded_state(true);
        assert_eq!(
            builder_sharded.config.runtime_state_shape,
            crate::runtime::config::RuntimeStateShape::Sharded,
            "with_sharded_state(true) must flip the config shape to Sharded"
        );

        let builder_back_to_unified = RuntimeBuilder::new()
            .with_sharded_state(true)
            .with_sharded_state(false);
        assert_eq!(
            builder_back_to_unified.config.runtime_state_shape,
            crate::runtime::config::RuntimeStateShape::Unified,
            "with_sharded_state(false) must flip back to Unified"
        );
    }

    /// br-asupersync-8fuxnt / br-asupersync-sched-hot-path-perf-bt4y5f.2.2:
    /// the public builder gate is FLIPPED — `with_sharded_state(true)` +
    /// `build()` must construct a working runtime whose workers dispatch
    /// against ShardedState's shard-A table, with the embedded table never
    /// owning its tasks. This replaces the former rejection regression
    /// (`build_with_sharded_state_returns_config_error_pointing_at_tracking_bead`)
    /// now that the gate's stated preconditions (replay-fingerprint identity
    /// proof + label/loom coverage) landed.
    #[test]
    fn build_accepts_sharded_state_and_dispatches_via_shard_a() {
        init_test_logging();

        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .with_sharded_state(true)
            .build()
            .expect(
                "the Sharded shape must be publicly constructible after the \
                 8fuxnt gate flip",
            );
        let dispatch = runtime
            .inner
            .scheduler
            .dispatch_task_table()
            .expect("a public sharded build must dispatch against shard A");

        let (tx, rx) = std::sync::mpsc::channel();
        let handle = runtime.handle();
        let join = handle.spawn(async move {
            tx.send(7_u32).expect("sharded task send");
        });
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(10))
                .expect("public-sharded task must run"),
            7
        );
        drop(join);

        // Drain to quiescence: live tasks retire from the shard-A table and
        // the embedded table never owns a public-sharded task at any point.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let embedded = runtime
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .live_task_count();
            assert_eq!(
                embedded, 0,
                "the embedded table must never own public-sharded tasks"
            );
            let shard_a = dispatch
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .live_task_count();
            if shard_a == 0 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "public sharded runtime drains to zero live tasks \
                 (shard_a={shard_a})"
            );
            std::thread::yield_now();
        }
        assert!(
            runtime.is_quiescent(),
            "public sharded runtime must report quiescence through the \
             dispatch-table-aware B02 read"
        );
    }

    /// br-asupersync-sched-hot-path-perf-bt4y5f.2.2 / E1.2 row T02: the
    /// scheduler's zero-acquisition constructor defers the parked-worker
    /// coordinator install to an explicit caller step, so `Runtime::new`
    /// must perform that step itself. Without it, a deferred cancellation
    /// batch minted while every worker is parked would set the readiness
    /// flag but wake nobody. This pins the builder's install call.
    #[test]
    fn runtime_new_installs_pending_cancel_dispatch_coordinator() {
        init_test_logging();

        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .build()
            .expect("build single-worker runtime");
        let installed = runtime
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .has_pending_cancel_dispatch_coordinator();
        assert!(
            installed,
            "Runtime::new must install the deferred-cancel coordinator \
             before worker threads start parking"
        );
    }

    #[derive(Debug)]
    enum NativeShutdownCommand {
        Legacy,
        Bounded(Budget),
        Close,
    }

    struct NativeShutdownProbe {
        region: crate::types::RegionId,
        polls: Arc<AtomicUsize>,
        wakes: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
        observed_cx: Arc<parking_lot::Mutex<Option<Cx>>>,
        wake_again: bool,
        retired: std::sync::mpsc::Sender<()>,
        _resource: crate::sync::OwnedMutexGuard<()>,
    }

    impl Future for NativeShutdownProbe {
        type Output = ();

        fn poll(self: Pin<&mut Self>, poll_cx: &mut Context<'_>) -> Poll<()> {
            let cx = Cx::current().expect("actual native finalizer task context");
            assert_eq!(cx.region_id(), self.region);
            assert!(cx.inner.read().mask_depth > 0);
            assert!(
                cx.checkpoint().is_ok(),
                "cleanup really runs under its mask"
            );
            *self.observed_cx.lock() = Some(cx);
            self.polls.fetch_add(1, Ordering::SeqCst);
            if self.wake_again {
                self.wakes.fetch_add(1, Ordering::SeqCst);
                poll_cx.waker().wake_by_ref();
            }
            Poll::Pending
        }
    }

    impl Drop for NativeShutdownProbe {
        fn drop(&mut self) {
            assert_eq!(self.drops.fetch_add(1, Ordering::SeqCst), 0);
            self.retired
                .send(())
                .expect("owned test still awaits retirement");
        }
    }

    fn wait_native_shutdown_condition(mut ready: impl FnMut() -> bool, message: &str) {
        let started = Instant::now();
        while !ready() {
            assert!(started.elapsed() < Duration::from_secs(10), "{message}");
            std::thread::yield_now();
        }
    }

    fn wait_native_shutdown_parked(runtime: &Runtime, task: crate::types::TaskId) {
        wait_native_shutdown_condition(
            || {
                let injector = runtime.inner.scheduler.global_injector();
                if injector.cancel_count() != 0 {
                    return false;
                }
                let stored_without_wake =
                    if let Some(table) = runtime.inner.scheduler.dispatch_task_table() {
                        let mut table = table
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        table.get_stored_future(task).is_some()
                            && table
                                .task(task)
                                .is_some_and(|record| !record.wake_state.is_notified())
                    } else {
                        let mut state = runtime
                            .inner
                            .state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        state.get_stored_future(task).is_some()
                            && state
                                .task(task)
                                .is_some_and(|record| !record.wake_state.is_notified())
                    };
                stored_without_wake && injector.cancel_count() == 0
            },
            "actual Pending finalizer must return to its dispatch table without a pending wake or queued cancellation",
        );
    }

    fn native_shutdown_budget_case(sharded: bool, case: u8) {
        use crate::cx::ChildRegionSpec;
        use crate::error::ErrorKind;
        use crate::record::finalizer::FinalizerBudgetError;
        use crate::record::region::RegionCloseOutcome;
        use crate::types::Outcome;

        let runtime = if sharded {
            RuntimeBuilder::new()
                .worker_threads(2)
                .with_sharded_state(true)
        } else {
            RuntimeBuilder::current_thread()
        }
        .build()
        .expect("native cleanup runtime");
        assert_eq!(runtime.config().worker_threads, if sharded { 2 } else { 1 });
        assert_eq!(runtime.inner.sharded_state.is_some(), sharded);
        assert_eq!(
            runtime.inner.scheduler.dispatch_task_table().is_some(),
            sharded
        );
        let (opened_tx, opened_rx) = std::sync::mpsc::channel();
        let (commands, mut command_rx) = crate::channel::mpsc::channel(4);
        let reason = CancelReason::user("native bounded finalizer cleanup");
        let owner_reason = reason.clone();
        let owner: Pin<Box<dyn Future<Output = (RegionCloseOutcome, Time)> + Send>> =
            Box::pin(async move {
                let cx = Cx::current().expect("actual native region owner");
                let child = cx
                    .open_child_region(ChildRegionSpec::inherit())
                    .await
                    .unwrap();
                opened_tx.send((child.region_id(), cx.task_id())).unwrap();
                loop {
                    match command_rx.recv(&cx).await.unwrap() {
                        NativeShutdownCommand::Legacy => child
                            .cancel(CancelReason::user("native legacy cleanup first"))
                            .unwrap(),
                        NativeShutdownCommand::Bounded(budget) => child
                            .cancel_with_budget(owner_reason.clone(), budget)
                            .unwrap(),
                        NativeShutdownCommand::Close => {
                            return (child.close_with_outcome().await.unwrap(), cx.now());
                        }
                    }
                }
            });
        let owner = runtime.handle().spawn(owner);
        let (region, owner_task) = opened_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("native child region admission");
        let polls = Arc::new(AtomicUsize::new(0));
        let wakes = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let observed_cx = Arc::new(parking_lot::Mutex::new(None));
        let resource = Arc::new(crate::sync::Mutex::new(()));
        let resource_guard = resource.try_lock_owned().unwrap();
        let (retired_tx, retired_rx) = std::sync::mpsc::channel();
        let (receipt, driver, shutdown_budget) = {
            let mut state = runtime
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let receipt = state.region(region).unwrap().close_receipt_handle();
            let shutdown_budget = state.region(region).unwrap().shutdown_budget_handle();
            assert!(state.register_async_finalizer(
                region,
                NativeShutdownProbe {
                    region,
                    polls: Arc::clone(&polls),
                    wakes: Arc::clone(&wakes),
                    drops: Arc::clone(&drops),
                    observed_cx: Arc::clone(&observed_cx),
                    wake_again: case == 1,
                    retired: retired_tx,
                    _resource: resource_guard,
                }
            ));
            (
                receipt,
                state
                    .timer_driver_handle()
                    .expect("native runtime timer authority"),
                shutdown_budget,
            )
        };
        assert!(resource.try_lock_owned().is_err());
        assert_eq!(driver.pending_count(), 0);
        let mut expected_deadline = None;
        let activation_poll_receipt = if case == 3 {
            commands.try_send(NativeShutdownCommand::Legacy).unwrap();
            wait_native_shutdown_condition(
                || polls.load(Ordering::SeqCst) == 1,
                "legacy finalizer is actually polled",
            );
            let finalizer_cx = observed_cx.lock().clone().unwrap();
            wait_native_shutdown_parked(&runtime, finalizer_cx.task_id());
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            assert_eq!(
                driver.pending_count(),
                0,
                "legacy None must not install a budget timer"
            );
            assert!(receipt.lock().is_none());
            assert!(
                runtime
                    .inner
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .region(region)
                    .unwrap()
                    .shutdown_budget()
                    .is_none()
            );
            let activated_deadline = driver.now().saturating_add_nanos(20_000_000_000);
            let activated_budget = Budget::INFINITE
                .with_poll_quota(8)
                .with_deadline(activated_deadline);
            commands
                .try_send(NativeShutdownCommand::Bounded(activated_budget))
                .unwrap();
            wait_native_shutdown_condition(
                || polls.load(Ordering::SeqCst) >= 2,
                "activation must publish a real wake to the parked legacy task",
            );
            wait_native_shutdown_parked(&runtime, finalizer_cx.task_id());
            // First cancellation publishes both the cancel route and the
            // installed CancelLaneWaker. Concurrent notification can also
            // reschedule a Pending poll. Bound actual callbacks by the
            // installed quota, rather than assuming one poll per command.
            let activation_polls = polls.load(Ordering::SeqCst);
            let active_poll_limit = usize::try_from(activated_budget.poll_quota).unwrap();
            assert!(activation_polls >= 2);
            assert!(activation_polls - 1 < active_poll_limit);
            assert_eq!(*shutdown_budget.read(), Some(activated_budget));
            // The budget is published before its deadline timer is armed, and
            // this thread reads both without the runtime lock. Wait for the arm
            // (bounded) instead of racing it on a loaded worker (asupersync-f5fadj).
            // A re-poll the activation scheduled re-arms the timer (cancel, then
            // register, under separate wheel locks), so the count and the
            // deadline are only meaningful read together: wait until both hold.
            wait_native_shutdown_condition(
                || {
                    driver.pending_count() == 1
                        && driver.next_deadline() == Some(activated_deadline)
                },
                "activation must arm exactly one shutdown-budget deadline timer",
            );
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            assert!(receipt.lock().is_none());
            let tightened_deadline = driver.now();
            expected_deadline = Some(tightened_deadline);
            let tightened_budget = Budget::INFINITE
                .with_poll_quota(4)
                .with_deadline(tightened_deadline);
            commands
                .try_send(NativeShutdownCommand::Bounded(tightened_budget))
                .unwrap();
            // Enqueueing the command is not the tightening receipt. Observe
            // the actual shared ceiling, which survives region retirement.
            wait_native_shutdown_condition(
                || *shutdown_budget.read() == Some(tightened_budget),
                "native command must apply the expired finalizer ceiling",
            );
            // A poll already admitted under the old ceiling can still enter
            // its callback while the command applies. This wrapper does not
            // preempt that poll. Wait for actual retirement before measuring
            // the finite callback count; the typed Deadline receipt below
            // proves the newly applied deadline caused cleanup termination.
            wait_native_shutdown_condition(
                || receipt.lock().is_some(),
                "expired ceiling must retire cleanup and publish actual close",
            );
            Some((activation_polls, active_poll_limit))
        } else {
            let budget = match case {
                0 => Budget::INFINITE.with_poll_quota(0),
                1 => Budget::INFINITE.with_poll_quota(3),
                2 => {
                    let deadline = driver.now().saturating_add_nanos(5_000_000_000);
                    expected_deadline = Some(deadline);
                    Budget::INFINITE.with_poll_quota(8).with_deadline(deadline)
                }
                _ => unreachable!(),
            };
            commands
                .try_send(NativeShutdownCommand::Bounded(budget))
                .unwrap();
            if case == 2 {
                wait_native_shutdown_condition(
                    || polls.load(Ordering::SeqCst) == 1,
                    "deadline cleanup actually parks",
                );
                let finalizer_cx = observed_cx.lock().clone().unwrap();
                assert!(driver.ptr_eq(&finalizer_cx.timer_driver().unwrap()));
                wait_native_shutdown_parked(&runtime, finalizer_cx.task_id());
                wait_native_shutdown_condition(
                    || driver.pending_count() == 1,
                    "deadline cleanup must arm exactly one shutdown-budget timer",
                );
                assert_eq!(driver.pending_count(), 1);
                assert_eq!(driver.next_deadline(), expected_deadline);
                assert!(driver.now() < expected_deadline.unwrap());
                assert_eq!(wakes.load(Ordering::SeqCst), 0);
                assert_eq!(drops.load(Ordering::SeqCst), 0);
                assert!(receipt.lock().is_none());
            }
            None
        };
        // This receive observes the actual future destructor. No host sleep,
        // manual timer processing, or synthetic wake drives deadline progress.
        retired_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("runtime must retire the actual bounded finalizer");
        wait_native_shutdown_condition(
            || receipt.lock().is_some(),
            "runtime must publish actual quiescent close receipt",
        );
        if let Some((activation_polls, active_poll_limit)) = activation_poll_receipt {
            let final_polls = polls.load(Ordering::SeqCst);
            assert!(final_polls >= activation_polls);
            assert!(final_polls - 1 < active_poll_limit);
        } else {
            assert_eq!(polls.load(Ordering::SeqCst), [0, 3, 1][usize::from(case)]);
        }
        assert_eq!(wakes.load(Ordering::SeqCst), if case == 1 { 3 } else { 0 });
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(driver.pending_count(), 0);
        drop(
            resource
                .try_lock_owned()
                .expect("retirement releases the actual physical guard"),
        );
        commands.try_send(NativeShutdownCommand::Close).unwrap();
        let (outcome, completed_at) = runtime.block_on(owner);
        let retained = receipt.lock().clone().unwrap();
        for actual in [&outcome, &retained] {
            let Some(Outcome::Err(error)) = &actual.cleanup_outcome else {
                panic!("exact finalizer-only budget failure missing: {actual:?}");
            };
            assert_eq!(
                error.kind(),
                if case < 2 {
                    ErrorKind::PollQuotaExhausted
                } else {
                    ErrorKind::DeadlineExceeded
                }
            );
            let failure = std::error::Error::source(error)
                .unwrap()
                .downcast_ref::<FinalizerBudgetError>()
                .expect("retained actual typed budget cause");
            if let Some(deadline) = expected_deadline {
                assert!(
                    matches!(failure, FinalizerBudgetError::Deadline { deadline: actual, observed } if *actual == deadline && *observed >= deadline && *observed <= completed_at)
                );
            } else {
                let limit = if case == 0 { 0 } else { 3 };
                assert_eq!(
                    *failure,
                    FinalizerBudgetError::PollQuota {
                        limit,
                        polled: limit
                    }
                );
            }
            if case == 3 {
                assert!(matches!(&actual.outcome, Outcome::Cancelled(actual) if actual == &reason));
            } else {
                assert!(
                    matches!(&actual.outcome, Outcome::Err(error) if error.kind() == ErrorKind::Internal)
                );
            }
        }
        wait_native_shutdown_condition(
            || runtime.is_quiescent(),
            "owner and finalizer really leave native dispatch",
        );
        let state = runtime
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(state.region(region).is_none());
        assert_eq!(state.live_task_count(), 0);
        assert_eq!(state.pending_obligation_count(), 0);
        assert_eq!(state.leak_count(), 0);
        assert_eq!(
            state.cancel_protocol_validator().lock().violation_count(),
            0,
            "actual finalizer retirement and region close preserve protocol accounting"
        );
        let trace = state.trace_handle().snapshot();
        drop(state);
        let finalizer_tasks: Vec<_> = trace
            .iter()
            .filter_map(|event| match event.data {
                crate::trace::TraceData::Task {
                    task,
                    region: actual,
                } if event.kind == TraceEventKind::Spawn && actual == region => Some(task),
                _ => None,
            })
            .collect();
        assert_eq!(finalizer_tasks.len(), 1);
        assert_ne!(finalizer_tasks[0], owner_task);
        assert_eq!(trace.iter().filter(|event| event.kind == TraceEventKind::Complete && matches!(event.data, crate::trace::TraceData::Task { task, region: actual } if task == finalizer_tasks[0] && actual == region)).count(), 1);
        if let Some(table) = runtime.inner.scheduler.dispatch_task_table() {
            assert_eq!(
                table
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .live_task_count(),
                0
            );
        }
        if let Some(shards) = &runtime.inner.sharded_state {
            assert_eq!(
                shards
                    .obligations
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .pending_count(),
                0
            );
            assert_eq!(shards.leak_count(), 0);
        }
        eprintln!(
            "native_shutdown_budget sharded={sharded} case={case} owner={owner_task:?} finalizer={:?} region={region:?} polls={} wakes={} drops=1 deadline={expected_deadline:?} completed_at={completed_at:?} receipt={outcome:?}",
            finalizer_tasks[0],
            polls.load(Ordering::SeqCst),
            wakes.load(Ordering::SeqCst)
        );
        drop(commands);
        drop(observed_cx);
        let inner = Arc::downgrade(&runtime.inner);
        assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
        assert!(inner.upgrade().is_none());
    }

    fn native_shutdown_budget_matrix(sharded: bool) {
        let (finished, result) = std::sync::mpsc::sync_channel(1);
        let owned = std::thread::Builder::new()
            .name(format!("native-shutdown-budget-{sharded}"))
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    for case in 0..4 {
                        native_shutdown_budget_case(sharded, case);
                    }
                }));
                finished
                    .send(outcome)
                    .expect("whole native journey watchdog remains alive");
            })
            .unwrap();
        let outcome = result
            .recv_timeout(Duration::from_secs(45))
            .expect("whole owned native cleanup journey exceeded 45 seconds");
        owned.join().unwrap();
        if let Err(payload) = outcome {
            std::panic::resume_unwind(payload);
        }
    }

    #[test]
    fn native_current_thread_shutdown_budget_runs_and_retires_real_finalizers() {
        native_shutdown_budget_matrix(false);
    }

    #[test]
    fn native_sharded_shutdown_budget_runs_and_retires_real_finalizers() {
        native_shutdown_budget_matrix(true);
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum NativeManagedFinalizerAction {
        Started,
        Work(u32),
        Failed(&'static str),
        FinalizerPending(crate::types::TaskId),
        FinalizerDone(crate::types::TaskId),
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct NativeManagedFinalizerEvent {
        child: usize,
        generation: crate::supervision::ManagedGeneration,
        action: NativeManagedFinalizerAction,
    }

    type NativeManagedFinalizerLog = Arc<parking_lot::Mutex<Vec<NativeManagedFinalizerEvent>>>;

    #[derive(Debug)]
    enum NativeManagedFinalizerCommand {
        Work(u32),
        Fail,
        Finish,
    }

    struct NativeManagedFinalizerReady {
        child: usize,
        generation: crate::supervision::ManagedGeneration,
        commands: crate::channel::mpsc::Sender<NativeManagedFinalizerCommand>,
    }

    struct NativeManagedHeldFinalizer {
        child: usize,
        generation: crate::supervision::ManagedGeneration,
        wait: Pin<Box<dyn Future<Output = ()> + Send>>,
        log: NativeManagedFinalizerLog,
        observed: Arc<parking_lot::Mutex<Option<Cx>>>,
        pending: bool,
        done: bool,
        _resource: crate::sync::OwnedMutexGuard<()>,
        _lease: Arc<()>,
    }

    impl Future for NativeManagedHeldFinalizer {
        type Output = ();

        fn poll(self: Pin<&mut Self>, poll_cx: &mut Context<'_>) -> Poll<()> {
            let this = self.get_mut();
            let cx = Cx::current().expect("registered native finalizer has its actual task Cx");
            assert_eq!(cx.region_id(), this.generation.region);
            assert_ne!(cx.task_id(), this.generation.task);
            assert!(cx.inner.read().mask_depth > 0);
            let task = cx.task_id();
            *this.observed.lock() = Some(cx);
            match this.wait.as_mut().poll(poll_cx) {
                Poll::Pending => {
                    if !this.pending {
                        this.pending = true;
                        this.log.lock().push(NativeManagedFinalizerEvent {
                            child: this.child,
                            generation: this.generation,
                            action: NativeManagedFinalizerAction::FinalizerPending(task),
                        });
                    }
                    Poll::Pending
                }
                Poll::Ready(()) => {
                    assert!(
                        this.pending,
                        "release follows actual Pending, not admission alone"
                    );
                    assert!(!this.done, "finalizer finishes exactly once");
                    this.done = true;
                    this.log.lock().push(NativeManagedFinalizerEvent {
                        child: this.child,
                        generation: this.generation,
                        action: NativeManagedFinalizerAction::FinalizerDone(task),
                    });
                    Poll::Ready(())
                }
            }
        }
    }

    fn native_managed_finalizer_replacement_claim(
        log: &[NativeManagedFinalizerEvent],
        affected: &[usize],
        claimed_replacement: bool,
    ) -> Result<(), &'static str> {
        if affected.is_empty() {
            return Err("zero_selected_finalizers");
        }
        let drained = |prefix: &[NativeManagedFinalizerEvent]| {
            affected.iter().all(|child| {
                prefix.iter().any(|event| {
                    event.child == *child
                        && event.generation.number == 1
                        && matches!(event.action, NativeManagedFinalizerAction::FinalizerDone(_))
                })
            })
        };
        for (index, event) in log.iter().enumerate() {
            if event.generation.number == 2
                && event.action == NativeManagedFinalizerAction::Started
                && !drained(&log[..index])
            {
                return Err("replacement_before_registered_finalizer_completion");
            }
        }
        if claimed_replacement && !drained(log) {
            return Err("replacement_before_registered_finalizer_completion");
        }
        Ok(())
    }

    fn native_managed_finalizer_generation_json(
        generation: crate::supervision::ManagedGeneration,
    ) -> serde_json::Value {
        serde_json::json!({
            "number": generation.number,
            "region": generation.region,
            "task": generation.task,
        })
    }

    fn native_managed_finalizer_replacement_case(
        sharded: bool,
        policy: crate::supervision::RestartPolicy,
    ) {
        use crate::channel::{mpsc, oneshot};
        use crate::supervision::{
            BackoffStrategy, ChildSpec, ManagedChildBinding, ManagedGeneration, ManagedRestartMode,
            ManagedSupervisorReport, RestartPolicy, SupervisionConfig, SupervisorBuilder,
        };
        use crate::trace::TraceData;
        use crate::types::Outcome;

        fn legacy_must_not_run(
            _: &crate::cx::Scope<'static, crate::types::policy::FailFast>,
            _: &mut RuntimeState,
            _: &Cx,
        ) -> Result<crate::types::TaskId, SpawnError> {
            panic!("managed binding must not invoke the legacy starter");
        }

        let runtime = if sharded {
            RuntimeBuilder::new()
                .worker_threads(2)
                .with_sharded_state(true)
        } else {
            RuntimeBuilder::current_thread()
        }
        .build()
        .expect("native managed finalizer runtime");
        assert_eq!(runtime.config().worker_threads, if sharded { 2 } else { 1 });
        assert_eq!(runtime.inner.sharded_state.is_some(), sharded);
        assert_eq!(
            runtime.inner.scheduler.dispatch_task_table().is_some(),
            sharded
        );
        let affected: &[usize] = match policy {
            RestartPolicy::OneForOne => &[1],
            RestartPolicy::OneForAll => &[0, 1, 2],
            RestartPolicy::RestForOne => &[1, 2],
        };
        let log: NativeManagedFinalizerLog = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let resources: Arc<Vec<_>> = Arc::new(
            (0..3)
                .map(|_| Arc::new(crate::sync::Mutex::new(())))
                .collect(),
        );
        // Only held finalizers clone a lease, so a count above one means an
        // original finalizer is still alive. Probing `resources` with
        // try_lock would take the lock, and concurrent replacements and the
        // test thread's own probes would then fail each other
        // (br-asupersync-bi2462.147.72).
        let leases: Arc<Vec<Arc<()>>> = Arc::new((0..3).map(|_| Arc::new(())).collect());
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let mut builder = SupervisorBuilder::new("native-registered-finalizer-replacement")
            .with_restart_policy(policy);
        let mut bindings = Vec::new();
        for (child, name) in ["a", "b", "c"].into_iter().enumerate() {
            let mut spec = ChildSpec::new(name, legacy_must_not_run)
                .with_shutdown_budget(Budget::new().with_poll_quota(17));
            if child != 0 {
                spec = spec.depends_on(["a", "b"][child - 1]);
            }
            builder = builder.child(spec);
            let ready_tx = ready_tx.clone();
            let log = Arc::clone(&log);
            let leases = Arc::clone(&leases);
            bindings.push(ManagedChildBinding::new(
                name,
                ManagedRestartMode::Transient,
                move |cx: Cx, generation: ManagedGeneration| {
                    let ready_tx = ready_tx.clone();
                    let log = Arc::clone(&log);
                    let leases = Arc::clone(&leases);
                    async move {
                        assert_eq!(cx.task_id(), generation.task);
                        assert_eq!(cx.region_id(), generation.region);
                        if generation.number == 2 {
                            assert!(leases.iter().all(|lease| Arc::strong_count(lease) == 1),
                                "replacement cannot run while any original finalizer owns its resource");
                        }
                        let (commands, mut receiver) = mpsc::channel(2);
                        log.lock().push(NativeManagedFinalizerEvent {
                            child,
                            generation,
                            action: NativeManagedFinalizerAction::Started,
                        });
                        ready_tx.send(NativeManagedFinalizerReady { child, generation, commands }).unwrap();
                        loop {
                            match receiver.recv(&cx).await {
                                Ok(NativeManagedFinalizerCommand::Work(value)) => {
                                    log.lock().push(NativeManagedFinalizerEvent {
                                        child,
                                        generation,
                                        action: NativeManagedFinalizerAction::Work(value),
                                    });
                                }
                                Ok(NativeManagedFinalizerCommand::Fail) => {
                                    let error = "native registered-finalizer trigger";
                                    log.lock().push(NativeManagedFinalizerEvent {
                                        child,
                                        generation,
                                        action: NativeManagedFinalizerAction::Failed(error),
                                    });
                                    return Outcome::Err(error);
                                }
                                Ok(NativeManagedFinalizerCommand::Finish) => return Outcome::Ok(()),
                                Err(mpsc::RecvError::Cancelled) => return Outcome::Cancelled(
                                    cx.cancel_reason().expect("affected child receives actual cancellation"),
                                ),
                                Err(error) => panic!("unexpected managed command loss: {error:?}"),
                            }
                        }
                    }
                },
            ));
        }
        drop(ready_tx);
        let managed = builder
            .compile()
            .unwrap()
            .bind_managed(
                bindings,
                SupervisionConfig::new(4, Duration::from_secs(60))
                    .with_restart_policy(policy)
                    .with_backoff(BackoffStrategy::None),
            )
            .unwrap();
        let owner_future: Pin<
            Box<
                dyn Future<Output = (ManagedSupervisorReport<&'static str>, crate::types::TaskId)>
                    + Send,
            >,
        > = Box::pin(async move {
            let cx = Cx::current().expect("actual registered native supervisor owner");
            let task = cx.task_id();
            (managed.run(&cx).await, task)
        });
        let owner = runtime.handle().spawn(owner_future);
        let mut original_ready = [None, None, None];
        for _ in 0..3 {
            let ready = ready_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("actual original managed factory");
            assert!(ready.child < original_ready.len());
            assert_eq!(ready.generation.number, 1);
            let child = ready.child;
            assert!(original_ready[child].replace(ready).is_none());
        }
        let mut current: Vec<_> = original_ready
            .into_iter()
            .map(|ready| ready.expect("every original child starts exactly once"))
            .collect();
        let originals: Vec<_> = current.iter().map(|ready| ready.generation).collect();
        let perform_work = |children: &[NativeManagedFinalizerReady], offset: u32| {
            for ready in children {
                let value = offset + u32::try_from(ready.child).unwrap();
                ready
                    .commands
                    .try_send(NativeManagedFinalizerCommand::Work(value))
                    .unwrap();
                wait_native_shutdown_condition(
                    || {
                        log.lock().contains(&NativeManagedFinalizerEvent {
                            child: ready.child,
                            generation: ready.generation,
                            action: NativeManagedFinalizerAction::Work(value),
                        })
                    },
                    "exact native worker payload acknowledgement",
                );
            }
        };
        perform_work(&current, 100);
        let mut releases = Vec::new();
        let mut observed = Vec::new();
        let mut receipts = Vec::new();
        for &child in affected {
            let (release, mut wait) = oneshot::channel();
            let observed_cx = Arc::new(parking_lot::Mutex::new(None));
            let resource = resources[child].try_lock_owned().unwrap();
            let finalizer = NativeManagedHeldFinalizer {
                child,
                generation: originals[child],
                wait: Box::pin(async move {
                    wait.recv_uninterruptible().await.unwrap();
                }),
                log: Arc::clone(&log),
                observed: Arc::clone(&observed_cx),
                pending: false,
                done: false,
                _resource: resource,
                _lease: Arc::clone(&leases[child]),
            };
            let mut state = runtime
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            receipts.push(
                state
                    .region(originals[child].region)
                    .unwrap()
                    .close_receipt_handle(),
            );
            assert!(state.register_async_finalizer(originals[child].region, finalizer));
            releases.push(Some(release));
            observed.push(observed_cx);
        }
        let driver = runtime
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .timer_driver_handle()
            .unwrap();
        assert_eq!(driver.pending_count(), 0);
        current[1]
            .commands
            .try_send(NativeManagedFinalizerCommand::Fail)
            .unwrap();
        wait_native_shutdown_condition(
            || {
                log.lock().contains(&NativeManagedFinalizerEvent {
                    child: 1,
                    generation: originals[1],
                    action: NativeManagedFinalizerAction::Failed(
                        "native registered-finalizer trigger",
                    ),
                })
            },
            "the original generation returns its real typed domain error",
        );

        // Cancellation can activate finalizers before the controller reaches
        // their close awaits. Observe actual Pending independently of that
        // scheduling order, releasing in the controller's reverse drain order.
        // The final held region outlives all previously released regions.
        let mut finalizer_tasks = Vec::new();
        for position in (0..affected.len()).rev() {
            let child = affected[position];
            wait_native_shutdown_condition(
                || {
                    log.lock().iter().any(|event| {
                        event.child == child
                            && event.generation == originals[child]
                            && matches!(
                                event.action,
                                NativeManagedFinalizerAction::FinalizerPending(_)
                            )
                    })
                },
                "actual registered finalizer crosses Pending",
            );
            let finalizer_cx = observed[position].lock().clone().unwrap();
            wait_native_shutdown_parked(&runtime, finalizer_cx.task_id());
            finalizer_tasks.push((child, finalizer_cx.task_id()));
            assert!(!owner.is_finished());
            assert!(!runtime.is_quiescent());
            assert!(resources[child].try_lock_owned().is_err());
            assert!(receipts[position].lock().is_none());
            let held = log.lock().clone();
            assert_eq!(
                native_managed_finalizer_replacement_claim(&held, affected, false),
                Ok(())
            );
            assert_eq!(
                native_managed_finalizer_replacement_claim(&held, affected, true),
                Err("replacement_before_registered_finalizer_completion")
            );
            assert_eq!(
                native_managed_finalizer_replacement_claim(&held, &[], true),
                Err("zero_selected_finalizers")
            );
            assert_eq!(
                held.iter()
                    .filter(|event| event.action == NativeManagedFinalizerAction::Started)
                    .count(),
                3
            );
            assert!(matches!(
                ready_rx.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ));
            {
                let state = runtime
                    .inner
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                assert!(state.region(originals[child].region).is_some());
                for &closed in &affected[position + 1..] {
                    assert!(
                        state.region(originals[closed].region).is_none(),
                        "the last held finalizer must outlive preceding affected closes"
                    );
                }
            }
            releases[position]
                .take()
                .unwrap()
                .send_blocking(())
                .unwrap();
            wait_native_shutdown_condition(
                || {
                    runtime
                        .inner
                        .state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .region(originals[child].region)
                        .is_none()
                },
                "released native registered finalizer closes its original region",
            );
            assert!(resources[child].try_lock_owned().is_ok());
            let receipt = receipts[position].lock().clone().unwrap();
            assert!(
                matches!(receipt.cleanup_outcome.as_ref(), Some(Outcome::Ok(()))),
                "{receipt:?}"
            );
        }
        let mut replacement_ready = [None, None, None];
        for _ in affected {
            let ready = ready_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("replacement after actual registered finalizer drain");
            let child = ready.child;
            assert!(affected.contains(&child));
            assert_eq!(ready.generation.number, 2);
            assert_ne!(ready.generation.task, originals[child].task);
            assert_ne!(ready.generation.region, originals[child].region);
            assert!(replacement_ready[child].replace(ready).is_none());
        }
        for &child in affected {
            let ready = replacement_ready[child]
                .take()
                .expect("every affected child restarts exactly once");
            assert!(matches!(
                current[child]
                    .commands
                    .try_send(NativeManagedFinalizerCommand::Fail),
                Err(mpsc::SendError::Disconnected(
                    NativeManagedFinalizerCommand::Fail
                ))
            ));
            current[child] = ready;
        }
        for ready in &current {
            if !affected.contains(&ready.child) {
                assert_eq!(ready.generation, originals[ready.child]);
            }
        }
        assert_eq!(
            native_managed_finalizer_replacement_claim(&log.lock(), affected, true),
            Ok(())
        );
        perform_work(&current, 200);
        for ready in &current {
            ready
                .commands
                .try_send(NativeManagedFinalizerCommand::Finish)
                .unwrap();
        }
        let (report, owner_task) = runtime.block_on(owner);
        assert!(report.outcome.is_ok(), "{report:?}");
        assert_eq!(report.started, 3 + affected.len() as u64);
        assert_eq!(report.joined, report.started);
        assert_eq!(report.restart_batches, 1);
        assert_eq!(report.escalations, 0);
        assert_eq!(report.children.len(), 3);
        for completed in &report.children {
            assert!(
                current
                    .iter()
                    .any(|ready| ready.generation == completed.generation)
            );
            assert!(
                completed.outcome.is_ok(),
                "latest generation finished its healthy work: {completed:?}"
            );
            assert!(completed.task_outcome.is_ok(), "{completed:?}");
            assert!(completed.region_outcome.is_some());
        }
        wait_native_shutdown_condition(
            || runtime.is_quiescent(),
            "all native managed generations and finalizers retire",
        );
        let state = runtime
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for generation in originals
            .iter()
            .chain(current.iter().map(|ready| &ready.generation))
        {
            assert!(state.region(generation.region).is_none());
        }
        assert!(state.region(report.region.unwrap()).is_none());
        assert_eq!(
            state.live_region_count(),
            1,
            "only the native runtime root remains before shutdown"
        );
        assert_eq!(state.live_task_count(), 0);
        assert_eq!(state.pending_obligation_count(), 0);
        assert_eq!(state.leak_count(), 0);
        assert_eq!(
            state.cancel_protocol_validator().lock().violation_count(),
            0
        );
        let trace = state.trace_handle().snapshot();
        drop(state);
        assert_eq!(driver.pending_count(), 0);
        if let Some(table) = runtime.inner.scheduler.dispatch_task_table() {
            assert_eq!(
                table
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .live_task_count(),
                0
            );
        }
        if let Some(shards) = &runtime.inner.sharded_state {
            assert_eq!(
                shards
                    .obligations
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .pending_count(),
                0
            );
            assert_eq!(shards.leak_count(), 0);
        }
        let log = log.lock().clone();
        let starts: Vec<_> = log
            .iter()
            .filter(|event| event.action == NativeManagedFinalizerAction::Started)
            .collect();
        let all_tasks: std::collections::BTreeSet<_> = starts
            .iter()
            .map(|event| event.generation.task)
            .chain(finalizer_tasks.iter().map(|(_, task)| *task))
            .chain([owner_task])
            .collect();
        assert_eq!(all_tasks.len(), starts.len() + finalizer_tasks.len() + 1);
        let task_seq = |task, region, kind| {
            let matches: Vec<_> = trace.iter().filter(|event| event.kind == kind &&
                matches!(event.data, TraceData::Task { task: actual, region: actual_region }
                    if actual == task && actual_region == region)).collect();
            assert_eq!(
                matches.len(),
                1,
                "exact canonical {kind:?} for {task:?}/{region:?}"
            );
            matches[0].seq
        };
        let close_seq = |region| {
            let matches: Vec<_> = trace.iter().filter(|event| event.kind == TraceEventKind::RegionCloseComplete &&
                matches!(event.data, TraceData::Region { region: actual, .. } if actual == region)).collect();
            assert_eq!(matches.len(), 1, "exact canonical close for {region:?}");
            matches[0].seq
        };
        for event in &starts {
            let generation = event.generation;
            assert!(
                task_seq(generation.task, generation.region, TraceEventKind::Complete)
                    < close_seq(generation.region)
            );
        }
        let mut ordered_joins = Vec::new();
        for &(child, finalizer) in &finalizer_tasks {
            let region = originals[child].region;
            let finalizer_start = task_seq(finalizer, region, TraceEventKind::Spawn);
            let finalizer_complete = task_seq(finalizer, region, TraceEventKind::Complete);
            let closed = close_seq(region);
            assert!(
                task_seq(originals[child].task, region, TraceEventKind::Complete) < finalizer_start
            );
            assert!(finalizer_start < finalizer_complete && finalizer_complete < closed);
            let replacements: Vec<_> = current.iter().filter(|ready| ready.generation.number == 2).map(|ready| {
                let spawned = task_seq(ready.generation.task, ready.generation.region, TraceEventKind::Spawn);
                assert!(closed < spawned, "every affected old finalizer/region closes before any replacement admission");
                spawned
            }).collect();
            ordered_joins.push(serde_json::json!({"child":child,"finalizer_task":finalizer,
                "original_region":region,"finalizer_spawn_seq":finalizer_start,
                "finalizer_complete_seq":finalizer_complete,"old_region_close_seq":closed,
                "replacement_spawn_seqs":replacements}));
        }
        let payloads: Vec<_> = log
            .iter()
            .filter_map(|event| match event.action {
                NativeManagedFinalizerAction::Work(value) => Some(value),
                _ => None,
            })
            .collect();
        assert_eq!(payloads, [100, 101, 102, 200, 201, 202]);
        assert_eq!(
            log.iter()
                .filter(|event| matches!(event.action, NativeManagedFinalizerAction::Failed(_)))
                .count(),
            1
        );
        assert_eq!(
            log.iter()
                .filter(|event| matches!(
                    event.action,
                    NativeManagedFinalizerAction::FinalizerPending(_)
                ))
                .count(),
            affected.len()
        );
        assert_eq!(
            log.iter()
                .filter(|event| matches!(
                    event.action,
                    NativeManagedFinalizerAction::FinalizerDone(_)
                ))
                .count(),
            affected.len()
        );
        let receipt = serde_json::json!({
            "backend":if sharded {"native_two_worker_sharded"} else {"native_current_thread"},
            "strategy":format!("{policy:?}"),"affected":affected,
            "originals":originals.iter().copied().map(native_managed_finalizer_generation_json).collect::<Vec<_>>(),
            "current":current.iter().map(|ready|native_managed_finalizer_generation_json(ready.generation)).collect::<Vec<_>>(),
            "started":report.started,"joined":report.joined,"restart_batches":report.restart_batches,
            "held_finalizer_witnesses":finalizer_tasks.len(),"ordered_joins":ordered_joins,"payloads":payloads,
            "trigger_error":"native registered-finalizer trigger","latest_outcomes":"Ok",
            "negative_controls":["zero_selected_finalizers","replacement_before_registered_finalizer_completion"],
            "live_tasks":0,"owned_regions":0,"runtime_roots_before_shutdown":1,
            "pending_obligations":0,"leaks":0,"pending_timers":0,"runtime_shutdown":true,
        });
        drop(current);
        drop(observed);
        let inner = Arc::downgrade(&runtime.inner);
        assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
        assert!(inner.upgrade().is_none());
        println!("ASUPERSYNC_NATIVE_MANAGED_FINALIZER_REPLACEMENT {receipt}");
    }

    fn native_managed_finalizer_replacement_matrix(sharded: bool) {
        let (finished, result) = std::sync::mpsc::sync_channel(1);
        let owned = std::thread::Builder::new()
            .name(format!("native-managed-finalizer-{sharded}"))
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    for policy in [
                        crate::supervision::RestartPolicy::OneForOne,
                        crate::supervision::RestartPolicy::OneForAll,
                        crate::supervision::RestartPolicy::RestForOne,
                    ] {
                        native_managed_finalizer_replacement_case(sharded, policy);
                    }
                }));
                finished
                    .send(outcome)
                    .expect("owned native matrix watchdog remains alive");
            })
            .unwrap();
        let outcome = result
            .recv_timeout(Duration::from_secs(45))
            .expect("native registered-finalizer replacement matrix exceeded 45 seconds");
        owned.join().unwrap();
        if let Err(payload) = outcome {
            std::panic::resume_unwind(payload);
        }
    }

    #[test]
    fn native_current_thread_managed_replacement_waits_for_registered_finalizers() {
        native_managed_finalizer_replacement_matrix(false);
    }

    #[test]
    fn native_sharded_managed_replacement_waits_for_registered_finalizers() {
        native_managed_finalizer_replacement_matrix(true);
    }

    /// asupersync-e74m5x: a local task that re-spawns its successor with
    /// `spawn_local` on every poll keeps the local spawn lane non-empty at
    /// every drain check. The post-root drain is bounded, so `block_on` must
    /// still return once its root has completed.
    #[test]
    fn current_thread_block_on_returns_despite_spawn_local_trampoline() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        fn respawn_forever(cx: &Cx, hops: std::sync::Arc<AtomicUsize>) {
            let next = std::sync::Arc::clone(&hops);
            let _ = cx.spawn_local(move |child| async move {
                next.fetch_add(1, Ordering::Relaxed);
                respawn_forever(&child, next);
            });
        }

        let (done_tx, done_rx) = std::sync::mpsc::channel::<(u8, usize)>();
        let _driver = std::thread::spawn(move || {
            let runtime = RuntimeBuilder::current_thread()
                .build()
                .expect("build current_thread runtime");
            let hops = std::sync::Arc::new(AtomicUsize::new(0));
            let counter = std::sync::Arc::clone(&hops);
            let value = runtime.block_on(async move {
                let cx = Cx::current().expect("root cx");
                respawn_forever(&cx, counter);
                42_u8
            });
            let _ = done_tx.send((value, hops.load(Ordering::Relaxed)));
            drop(runtime);
        });
        let (value, hops) = done_rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("block_on must return after its root despite a spawn_local trampoline");
        assert_eq!(value, 42);
        assert!(
            hops >= 1,
            "the trampoline must have run at least once before the bounded drain cut it off"
        );
    }

    /// asupersync-1fyc8f: a thread that ran `block_on` keeps that runtime's
    /// keyed local-task store (here holding a parked `!Send` task). Dropping
    /// the runtime on another thread must retire that store the next time the
    /// first thread touches its local stores; before, the store lived on
    /// under a heap-address key that a later runtime could reuse.
    #[test]
    fn keyed_local_store_is_purged_after_the_runtime_is_dropped_elsewhere() {
        use crate::runtime::local::{keyed_local_store_count, local_task_count};

        let (runtime_tx, runtime_rx) = std::sync::mpsc::channel::<Runtime>();
        let (dropped_tx, dropped_rx) = std::sync::mpsc::channel::<()>();
        let (counts_tx, counts_rx) = std::sync::mpsc::channel::<(usize, usize)>();
        let helper = std::thread::spawn(move || {
            let runtime = RuntimeBuilder::current_thread()
                .build()
                .expect("build current_thread runtime");
            runtime.block_on(async {
                let cx = Cx::current().expect("root cx");
                let _parked = cx
                    .spawn_local(|_| std::future::pending::<()>())
                    .expect("spawn_local from the root");
                // One dispatch turn admits the parked task into this thread's
                // keyed store.
                crate::runtime::yield_now().await;
            });
            let before = keyed_local_store_count();
            runtime_tx
                .send(runtime)
                .expect("hand the runtime to the dropping thread");
            dropped_rx.recv().expect("wait for the drop");
            // Any local-store operation on this thread must observe the
            // retirement.
            let _ = local_task_count();
            let after = keyed_local_store_count();
            counts_tx
                .send((before, after))
                .expect("report store counts");
        });

        let runtime = runtime_rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("helper hands over its runtime");
        drop(runtime);
        dropped_tx.send(()).expect("release the helper");
        let (before, after) = counts_rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("helper reports its keyed store counts");
        helper.join().expect("helper thread");
        assert_eq!(
            before, 1,
            "the parked !Send task keeps this runtime's keyed store on the block_on thread"
        );
        assert_eq!(
            after, 0,
            "dropping the runtime on another thread must retire that thread's keyed store on its next touch"
        );
    }

    fn assert_local_owner_exit_retires_admitted_tasks(sharded: bool) {
        use crate::runtime::task_handle::JoinError;

        struct ParkedLocal {
            index: usize,
            started: bool,
            starts: Arc<AtomicUsize>,
            drops: Arc<std::sync::Mutex<Vec<(usize, std::thread::ThreadId)>>>,
            _local: std::rc::Rc<()>,
        }

        impl Future for ParkedLocal {
            type Output = ();

            fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
                if !self.started {
                    self.started = true;
                    self.starts.fetch_add(1, Ordering::SeqCst);
                }
                Poll::Pending
            }
        }

        impl Drop for ParkedLocal {
            fn drop(&mut self) {
                self.drops
                    .lock()
                    .unwrap()
                    .push((self.index, std::thread::current().id()));
                if self.index == 0 {
                    panic!("parked local destructor");
                }
            }
        }

        // More than one consumer batch, with the first destructor panicking:
        // neither containment nor a bounded drain may strand later records.
        const TASKS: usize = 10;
        let drops = Arc::new(std::sync::Mutex::new(Vec::new()));
        let owner_drops = Arc::clone(&drops);
        let owner = std::thread::spawn(move || {
            let runtime = RuntimeBuilder::current_thread()
                .with_sharded_state(sharded)
                .build()
                .expect("build movable current-thread runtime");
            let starts = Arc::new(AtomicUsize::new(0));
            let handles = runtime.block_on(async {
                let cx = Cx::current().expect("root context");
                let mut handles = Vec::new();
                for index in 0..TASKS {
                    let task_starts = Arc::clone(&starts);
                    let task_drops = Arc::clone(&owner_drops);
                    handles.push(
                        cx.spawn_local(move |_| ParkedLocal {
                            index,
                            started: false,
                            starts: task_starts,
                            drops: task_drops,
                            _local: std::rc::Rc::new(()),
                        })
                        .expect("admit local task on the calling thread"),
                    );
                }
                for _ in 0..128 {
                    if starts.load(Ordering::SeqCst) == TASKS {
                        break;
                    }
                    crate::runtime::yield_now().await;
                }
                assert_eq!(starts.load(Ordering::SeqCst), TASKS);
                handles
            });
            assert!(owner_drops.lock().unwrap().is_empty());
            (runtime, handles, std::thread::current().id())
        });
        let (runtime, mut handles, owner_id) = owner
            .join()
            .expect("one local destructor panic must not escape thread teardown");
        {
            let retired = drops.lock().unwrap();
            assert_eq!(retired.len(), TASKS, "all owner-thread destructors finished");
            assert!(retired.iter().all(|(_, thread)| *thread == owner_id));
            let mut indexes: Vec<_> = retired.iter().map(|(index, _)| *index).collect();
            indexes.sort_unstable();
            assert_eq!(indexes, (0..TASKS).collect::<Vec<_>>());
        }

        assert_eq!(
            runtime.drain_root_region(Duration::from_secs(5)),
            RootDrainOutcome::Quiescent,
            "sharded={sharded}: owner-thread exit must not strand local records"
        );
        for (index, handle) in handles.iter_mut().enumerate() {
            assert!(handle.is_finished(), "local task {index} has retired");
            match handle.try_join() {
                Err(JoinError::Panicked(panic)) if index == 0 => {
                    assert_eq!(panic.message(), "parked local destructor");
                }
                Err(JoinError::Cancelled(reason)) if index != 0 => {
                    assert!(reason.is_shutdown());
                }
                other => panic!("sharded={sharded}: local task {index} joined as {other:?}"),
            }
            let task_id = handle.task_id();
            if let Some(table) = runtime.inner.scheduler.dispatch_task_table() {
                assert!(
                    table
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .task(task_id)
                        .is_none()
                );
            } else {
                assert!(
                    runtime
                        .inner
                        .state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .task(task_id)
                        .is_none()
                );
            }
        }
        assert!(runtime.is_quiescent());
    }

    #[test]
    fn exited_local_owner_releases_joins_and_root_drain() {
        assert_local_owner_exit_retires_admitted_tasks(false);
    }

    #[test]
    fn exited_local_owner_retires_sharded_records_and_destructor_panics() {
        assert_local_owner_exit_retires_admitted_tasks(true);
    }

    #[test]
    fn browser_host_services_pump_contract_and_local_future_resolution() {
        use std::cell::Cell;
        use std::rc::Rc;

        let host_services = Arc::new(BrowserHostServices::with_burst_limit(4));

        // 1. Threadless startup check. The pump requires exactly one worker;
        // the builder's default worker count follows the host's parallelism,
        // so pin it or this test only passes on single-worker machines.
        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .browser_host_services(host_services)
            .build()
            .expect("threadless runtime builder build succeeds");

        assert!(
            lock_state(&runtime.inner.worker_threads).is_empty(),
            "BrowserHostServices must not spawn worker threads"
        );
        let runtime_pump = runtime.browser_pump().expect("browser pump present");
        assert_eq!(runtime_pump.microtask_burst_limit(), 4);

        // 2. Nonreentrancy guard check
        runtime_pump.in_pump.store(true, Ordering::SeqCst);
        let outcome = runtime_pump.drain_batch(10);
        assert_eq!(outcome, PumpDrainOutcome::ReentrantPrevented);
        runtime_pump.in_pump.store(false, Ordering::SeqCst);

        // 3. Bounded burst limit check: spawn 10 tasks
        let counter = Rc::new(Cell::new(0u32));
        let mut handles = Vec::new();
        for _ in 0..10 {
            let c = Rc::clone(&counter);
            handles.push(runtime.spawn_local(async move {
                c.set(c.get() + 1);
            }));
        }

        // With burst limit 4, draining batches of 4 tasks hits burst limit
        let batch1 = runtime_pump.drain_batch(4);
        assert_eq!(batch1, PumpDrainOutcome::BurstLimitReached(4));

        let batch2 = runtime_pump.drain_batch(4);
        assert_eq!(batch2, PumpDrainOutcome::BurstLimitReached(4));

        let batch3 = runtime_pump.drain_batch(4);
        assert_eq!(batch3, PumpDrainOutcome::Completed(2));

        let batch4 = runtime_pump.drain_batch(4);
        assert_eq!(batch4, PumpDrainOutcome::Idle);

        assert_eq!(counter.get(), 10);
        for handle in handles {
            assert!(handle.is_finished());
        }

        // 4. Local !Send future resolution check
        let value = Rc::new(Cell::new(100u32));
        let val_clone = Rc::clone(&value);
        let mut handle = runtime.spawn_local(async move {
            val_clone.set(val_clone.get() + 23);
            val_clone.get()
        });

        assert!(!handle.is_finished());
        let drained = runtime_pump.run_until_idle();
        assert_eq!(drained, 1);
        assert!(handle.is_finished());
        assert_eq!(value.get(), 123);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let result = Pin::new(&mut handle).poll(&mut cx);
        assert_eq!(result, Poll::Ready(Ok(123)));

        // 4b. Local future with !Send output (real Rc output regression for E0277)
        let mut rc_handle = runtime.spawn_local(async move { Rc::new(42u32) });
        assert!(!rc_handle.is_finished());
        assert_eq!(runtime_pump.run_until_idle(), 1);
        assert!(rc_handle.is_finished());
        let mut rc_cx = Context::from_waker(&waker);
        match Pin::new(&mut rc_handle).poll(&mut rc_cx) {
            Poll::Ready(Ok(rc_val)) => assert_eq!(*rc_val, 42),
            other => panic!("expected Ready(Ok(Rc(42))), got {other:?}"),
        }

        // 5. BrowserWorkerPump::step single-step execution check with a real spawned local future
        let step_value = Rc::new(Cell::new(200u32));
        let step_val_clone = Rc::clone(&step_value);
        let mut step_handle = runtime.spawn_local(async move {
            step_val_clone.set(step_val_clone.get() + 42);
            step_val_clone.get()
        });

        assert!(!step_handle.is_finished());
        // step() must return true when executing the task, not false due to BurstLimitReached(1)
        assert!(
            runtime_pump.step(),
            "step() must return true when a task was executed"
        );
        assert!(step_handle.is_finished());
        assert_eq!(step_value.get(), 242);

        // Additional step when idle must return false
        assert!(
            !runtime_pump.step(),
            "step() must return false when queues are idle"
        );

        let mut step_cx = Context::from_waker(&waker);
        let step_result = Pin::new(&mut step_handle).poll(&mut step_cx);
        assert_eq!(step_result, Poll::Ready(Ok(242)));

        // 6. Self-waking local future burst-limit enforcement and multi-batch resolution
        let sw_counter = Rc::new(Cell::new(0u32));
        let sw_clone = Rc::clone(&sw_counter);
        struct SelfWaker {
            remaining: u32,
            count: Rc<Cell<u32>>,
        }
        impl std::future::Future for SelfWaker {
            type Output = u32;
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                self.count.set(self.count.get() + 1);
                if self.remaining == 0 {
                    Poll::Ready(self.count.get())
                } else {
                    self.remaining -= 1;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }
        let mut sw_handle = runtime.spawn_local(SelfWaker {
            remaining: 5,
            count: sw_clone,
        });
        // runtime_pump has burst limit 4; draining a burst of 4 should yield BurstLimitReached(4)
        let sw_batch1 = runtime_pump.drain_batch(4);
        assert_eq!(sw_batch1, PumpDrainOutcome::BurstLimitReached(4));
        assert!(!sw_handle.is_finished());
        assert_eq!(sw_counter.get(), 4);

        // Second batch completes the remaining 2 steps (5th poll + 6th final poll)
        let sw_batch2 = runtime_pump.drain_batch(4);
        assert_eq!(sw_batch2, PumpDrainOutcome::Completed(2));
        assert!(sw_handle.is_finished());
        assert_eq!(sw_counter.get(), 6);

        let mut sw_cx = Context::from_waker(&waker);
        assert_eq!(
            Pin::new(&mut sw_handle).poll(&mut sw_cx),
            Poll::Ready(Ok(6))
        );

        // 7. Cancelled/dropped before completion returns Err(JoinError::Cancelled) rather than panicking
        let mut cancelled_handle = runtime.spawn_local(std::future::pending::<u32>());
        assert!(!cancelled_handle.is_finished());
        drop(runtime);
        assert!(cancelled_handle.is_finished());

        let mut cx2 = Context::from_waker(&waker);
        match Pin::new(&mut cancelled_handle).poll(&mut cx2) {
            Poll::Ready(Err(crate::runtime::JoinError::Cancelled(reason))) => {
                assert!(reason.is_shutdown());
            }
            other => panic!("expected cancelled join error, got {other:?}"),
        }
        assert_eq!(
            Pin::new(&mut cancelled_handle).poll(&mut cx2),
            Poll::Ready(Err(crate::runtime::JoinError::PolledAfterCompletion))
        );
    }

    /// br-asupersync-1pi7ne H1, trigger (b): a task that holds a strong
    /// `RuntimeHandle` (an accept loop spawning through a handle) used to keep
    /// the runtime alive forever. shutdown_timeout signalled the workers, but
    /// the task was never dropped, so its handle was never released, teardown
    /// never ran and the reaper spun. Now the reaper drops the stopped task
    /// and teardown completes within the bound.
    #[test]
    fn shutdown_timeout_retires_a_task_that_holds_a_strong_runtime_handle() {
        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .build()
            .expect("build runtime");
        let runtime_inner = Arc::downgrade(&runtime.inner);
        let held = runtime.handle();
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let _join = runtime.handle().spawn(async move {
            let _held = held;
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx
            .recv_timeout(Duration::from_secs(60))
            .expect("the task that holds the handle started");

        assert!(
            runtime.shutdown_timeout(Duration::from_secs(10)),
            "teardown never completed: the stopped task kept its strong RuntimeHandle"
        );
        assert!(
            runtime_inner.upgrade().is_none(),
            "the runtime state was released"
        );
    }

    /// br-asupersync-1pi7ne H1, trigger (a): a `block_on` caller on a cloned
    /// `Runtime` that waits for a task used to wait forever after
    /// shutdown_timeout. The task was frozen, never polled or dropped, and the
    /// caller's clone kept teardown from running. Now the reaper drops the
    /// task, the join observes it ("task was dropped or cancelled before
    /// completion"), the caller returns and releases its clone, and teardown
    /// completes.
    #[test]
    fn shutdown_timeout_ends_a_block_on_caller_waiting_on_a_clone() {
        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .build()
            .expect("build runtime");
        let clone = runtime.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let (returned_tx, returned_rx) = std::sync::mpsc::channel::<bool>();
        std::thread::spawn(move || {
            let waited = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                clone.block_on(async move {
                    let task = Runtime::current_handle()
                        .expect("block_on installs a handle")
                        .spawn(std::future::pending::<()>());
                    let _ = started_tx.send(());
                    task.await;
                });
            }));
            drop(clone);
            let _ = returned_tx.send(waited.is_err());
        });
        started_rx
            .recv_timeout(Duration::from_secs(60))
            .expect("the block_on caller spawned its task");

        let completed = runtime.shutdown_timeout(Duration::from_secs(10));
        let join_failed = returned_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the block_on caller never returned: its task was not retired");
        assert!(join_failed, "the join observed the task's cancellation");
        assert!(
            completed,
            "teardown completed once the caller released its clone"
        );
    }

    /// br-asupersync-1pi7ne M1: shutdown_timeout returned `true` while a
    /// blocking-pool job was still running. The final drop waits for the
    /// pool's threads at most 5 s and discards the result, and the reaper then
    /// reported a completed teardown. The bound here is well past those 5 s.
    #[test]
    fn shutdown_timeout_is_incomplete_while_a_blocking_job_still_runs() {
        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .blocking_threads(1, 1)
            .build()
            .expect("build runtime");
        let shutdown_complete = Arc::clone(&runtime.inner.shutdown_completion);
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let job = runtime
            .spawn_blocking(move || {
                let _ = started_tx.send(());
                let _ = release_rx.recv_timeout(Duration::from_secs(120));
            })
            .expect("the runtime has a blocking pool");
        started_rx
            .recv_timeout(Duration::from_secs(60))
            .expect("the blocking job started");

        assert!(
            !runtime.shutdown_timeout(Duration::from_secs(8)),
            "teardown reported complete while a blocking job still runs"
        );
        assert!(!job.is_done(), "the blocking job is still running");
        release_tx.send(()).expect("the blocking job still waits");
        assert!(job.wait_timeout(Duration::from_secs(10)));
        assert!(
            shutdown_complete.wait_timeout(Duration::from_secs(10)),
            "the reaper finishes teardown once the job ends"
        );
    }

    /// br-asupersync-1pi7ne M1, the positive side: a blocking job that ends
    /// within the bound has ended when shutdown_timeout returns `true`.
    #[test]
    fn shutdown_timeout_waits_for_a_blocking_job_that_ends_within_the_bound() {
        let runtime = RuntimeBuilder::new()
            .worker_threads(1)
            .blocking_threads(1, 1)
            .build()
            .expect("build runtime");
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let ended = Arc::new(AtomicBool::new(false));
        let job_ended = Arc::clone(&ended);
        let _job = runtime
            .spawn_blocking(move || {
                let _ = started_tx.send(());
                std::thread::sleep(Duration::from_millis(300));
                job_ended.store(true, Ordering::SeqCst);
            })
            .expect("the runtime has a blocking pool");
        started_rx
            .recv_timeout(Duration::from_secs(60))
            .expect("the blocking job started");

        assert!(runtime.shutdown_timeout(Duration::from_secs(30)));
        assert!(
            ended.load(Ordering::SeqCst),
            "teardown completed before the blocking job ended"
        );
    }

    /// GitHub #80 census: the shutdown reaper's handle used to be dropped at
    /// spawn, detaching a thread that may already be exiting. While the
    /// reaper still runs, its handle is parked instead, and it is joined once
    /// the thread has finished.
    #[test]
    fn a_running_shutdown_reaper_is_parked_not_detached() {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build runtime");
        let shutdown_complete = Arc::clone(&runtime.inner.shutdown_completion);
        let retained = runtime.clone();

        // The clone keeps the reaper waiting for sole ownership of the runtime.
        assert!(!runtime.shutdown_timeout(Duration::ZERO));
        assert_eq!(
            crate::runtime::spawn_blocking::parked_thread_named("asupersync-shutdown"),
            Some(false),
            "the running reaper must be parked, not detached"
        );

        drop(retained);
        assert!(shutdown_complete.wait_timeout(Duration::from_secs(10)));
    }

    /// br-asupersync-01oghn M1: a `spawn_local` request still queued on a
    /// worker thread's lane when the runtime stops resolves as cancelled on
    /// that thread before it exits. This holds for a multi-thread worker and
    /// for the current-thread runtime's background thread. Before, thread
    /// exit dropped the request unresolved, and its handle never finished.
    #[test]
    fn a_local_spawn_queued_when_its_worker_stops_resolves_cancelled() {
        let mut unresolved = Vec::new();
        for current_thread in [false, true] {
            let runtime = if current_thread {
                RuntimeBuilder::current_thread().build()
            } else {
                RuntimeBuilder::new().worker_threads(1).build()
            }
            .expect("build runtime");
            let stopping = runtime.inner.scheduler.shutdown_signal_for_test();
            let (local_tx, local_rx) = std::sync::mpsc::channel();
            let _pin = runtime.handle().spawn(async move {
                let local = Cx::current()
                    .expect("task cx")
                    .spawn_local(|_| async { 7_u8 })
                    .expect("queue a local spawn on this worker");
                local_tx.send(local).expect("test thread takes the handle");
                // The dispatch loop checks shutdown before it drains the
                // local spawn lane, so the request above stays queued.
                while !stopping.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
            });
            let mut local = local_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("the worker runs the pinning task");
            drop(runtime);
            let joined = local.try_join();
            if !matches!(joined, Err(crate::runtime::JoinError::Cancelled(_))) {
                unresolved.push(format!("current_thread={current_thread}: {joined:?}"));
            }
        }
        assert!(
            unresolved.is_empty(),
            "queued local spawns did not resolve cancelled: {unresolved:?}"
        );
    }

    /// frankenterm#135: a `block_on` caller that fires a due timer runs that
    /// timer's own waker and nothing else. It used to broadcast `wake_all()`
    /// on top, unparking every worker and the reactor for each fired batch.
    #[test]
    fn block_on_timer_processing_runs_only_the_fired_wakers() {
        struct CountingWaker(AtomicUsize);
        impl std::task::Wake for CountingWaker {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        init_test_logging();
        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .build()
            .expect("runtime build");
        // A driver only this thread knows about, so no worker can fire the
        // timer first and the assertions below are deterministic.
        let clock = Arc::new(crate::time::VirtualClock::starting_at(Time::from_secs(1)));
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let cx = Cx::new_with_drivers(
            crate::types::RegionId::new_for_test(0, 135),
            crate::types::TaskId::new_for_test(0, 135),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer.clone()),
            None,
        );
        let fired = Arc::new(CountingWaker(AtomicUsize::new(0)));
        let _registration = timer.register(Time::from_secs(2), Waker::from(Arc::clone(&fired)));
        clock.advance_to(Time::from_secs(2));

        let _runtime_guard = ScopedRuntimeHandle::new(runtime.handle());
        let _cx_guard = Cx::set_current(Some(cx));
        let broadcasts_before =
            crate::runtime::scheduler::three_lane::wake_all_calls_on_this_thread();

        assert!(process_current_block_on_timers(), "the due timer fires");
        assert_eq!(
            fired.0.load(Ordering::SeqCst),
            1,
            "the fired timer's waker runs exactly once"
        );
        assert_eq!(
            crate::runtime::scheduler::three_lane::wake_all_calls_on_this_thread()
                - broadcasts_before,
            0,
            "firing a timer must not broadcast an unpark to every worker"
        );
        assert!(
            !process_current_block_on_timers(),
            "no further timer is due"
        );
    }
