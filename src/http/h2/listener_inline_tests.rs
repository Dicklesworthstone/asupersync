    use super::*;
    use crate::http::body::Body as _;

    #[test]
    fn accept_resource_exhaustion_retries_out_of_memory() {
        assert!(is_transient_accept_error(&io::Error::from(
            io::ErrorKind::OutOfMemory
        )));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn accept_resource_exhaustion_retries_native_errors() {
        #[cfg(unix)]
        let codes = [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM];
        #[cfg(windows)]
        let codes = {
            use windows_sys::Win32::Networking::WinSock::{WSAEMFILE, WSAENOBUFS};
            [WSAEMFILE, WSAENOBUFS]
        };

        for code in codes {
            let error = io::Error::from_raw_os_error(code);
            assert!(
                is_transient_accept_error(&error),
                "resource exhaustion must reach accept backoff: {error:?}"
            );
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn accept_resource_exhaustion_preserves_native_fatal_errors() {
        #[cfg(unix)]
        let codes = [libc::EBADF, libc::ENOTSOCK, libc::EINVAL, libc::EACCES];
        #[cfg(windows)]
        let codes = {
            use windows_sys::Win32::Networking::WinSock::{WSAEACCES, WSAEINVAL, WSAENOTSOCK};
            [WSAENOTSOCK, WSAEINVAL, WSAEACCES]
        };

        for code in codes {
            let error = io::Error::from_raw_os_error(code);
            assert!(
                !is_transient_accept_error(&error),
                "permanent accept errors must still terminate the listener: {error:?}"
            );
        }
    }

    fn owned_hop_config() -> OwnedH2HopConfig {
        OwnedH2HopConfig {
            budget: Budget::INFINITE,
            started_at: Time::ZERO,
            source: RequestBudgetSource::Inherited,
            drain_grace: Duration::from_nanos(100),
            idle_timeout: None,
        }
    }

    struct OwnedBodyDrop {
        cx: Cx,
        dropped: Arc<AtomicUsize>,
        cancelled: Arc<AtomicUsize>,
    }

    impl Drop for OwnedBodyDrop {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::SeqCst);
            if self.cx.is_cancel_requested() {
                self.cancelled.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    fn finish_owned_h2_lab(lab: &mut crate::lab::LabRuntime, root: crate::types::RegionId) {
        assert_eq!(lab.state.live_task_count(), 0);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert_eq!(lab.state.regions_len(), 1, "only the actual root remains");
        assert!(lab.state.region(root).is_some());
        assert!(
            lab.state
                .timer_driver_handle()
                .unwrap()
                .next_deadline()
                .is_none()
        );
        assert!(lab.run_until_quiescent_with_report().lab_test_passed());
        lab.state
            .close_region_command(root, &CancelReason::user("owned H2 test finished"));
        assert!(lab.run_until_idle() < 1024);
        assert_eq!(lab.state.regions_len(), 0);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert!(
            lab.state
                .timer_driver_handle()
                .unwrap()
                .next_deadline()
                .is_none()
        );
        assert!(lab.run_until_quiescent_with_report().lab_test_passed());
    }

    #[test]
    fn owned_h2_request_force_close_drains_actual_body_and_descendant() {
        for seed in [0x36_100, 0x36_101, 0x36_102] {
            for parent_cancel in [false, true] {
                owned_h2_force_close_case(seed, parent_cancel);
            }
        }
    }

    fn owned_h2_force_close_case(seed: u64, parent_cancel: bool) {
        use crate::channel::oneshot;
        use crate::lab::{LabConfig, LabRuntime};
        let mut lab = LabRuntime::new(LabConfig::new(seed).max_steps(2048));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let signal = ShutdownSignal::new();
        let task_signal = signal.clone();
        let body_cx = Arc::new(parking_lot::Mutex::new(None::<Cx>));
        let identity = Arc::clone(&body_cx);
        let cleanup = Arc::new(AtomicUsize::new(0));
        let entered = Arc::clone(&cleanup);
        let dropped = Arc::new(AtomicUsize::new(0));
        let retired = Arc::clone(&dropped);
        let cancelled = Arc::new(AtomicUsize::new(0));
        let observed_cancel = Arc::clone(&cancelled);
        let in_flight = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&in_flight);
        let result = Arc::new(parking_lot::Mutex::new(None));
        let published = Arc::clone(&result);
        let (release_body, mut body_cleanup) = oneshot::channel();
        let (release_child, mut child_cleanup) = oneshot::channel();
        let (owner, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                let _guard = InFlightRequestGuard::acquire(Some(&counter));
                let completed =
                    run_owned_h2_hop(&cx, &task_signal, owned_hop_config(), move || async move {
                        let cx = Cx::current().expect("actual body context");
                        *identity.lock() = Some(cx.clone());
                        let _drop = OwnedBodyDrop {
                            cx: cx.clone(),
                            dropped: retired,
                            cancelled: observed_cancel,
                        };
                        let child_entered = Arc::clone(&entered);
                        let _descendant = cx
                            .spawn(move |child| async move {
                                let (_sender, mut receiver) = mpsc::channel::<()>(1);
                                assert_eq!(
                                    receiver.recv(&child).await,
                                    Err(mpsc::RecvError::Cancelled)
                                );
                                child_entered.fetch_add(1, Ordering::SeqCst);
                                child_cleanup.recv_uninterruptible().await.unwrap();
                            })
                            .unwrap();
                        let token = cx
                            .try_register_obligation_checked(
                                crate::record::ObligationKind::Lease,
                                cx.task_id(),
                            )
                            .unwrap()
                            .unwrap();
                        assert!(token.commit(), "actual admitted body retains its gateway");
                        let (_sender, mut receiver) = mpsc::channel::<()>(1);
                        assert_eq!(receiver.recv(&cx).await, Err(mpsc::RecvError::Cancelled));
                        entered.fetch_add(1, Ordering::SeqCst);
                        body_cleanup.recv_uninterruptible().await.unwrap();
                        H2DispatchResponse::Buffered(
                            Response::new(200, "OK", b"drained".to_vec()).into_h2_response(),
                        )
                    })
                    .await
                    .unwrap();
                *published.lock() = Some(completed);
            })
            .unwrap();
        lab.scheduler.lock().schedule(owner, 0);
        assert!(lab.run_until_idle() < 2048);
        let body = body_cx.lock().clone().expect("body actually polled");
        assert_ne!(body.task_id(), owner);
        assert_ne!(body.region_id(), root);
        assert_eq!(
            lab.state.task(body.task_id()).unwrap().owner,
            body.region_id()
        );
        assert_eq!(lab.state.tasks_len(), 3);
        if parent_cancel {
            lab.state
                .task(owner)
                .unwrap()
                .cx
                .as_ref()
                .unwrap()
                .cancel_with(CancelKind::User, Some("explicit parent Cx cancellation"));
        } else {
            assert!(signal.begin_drain(Duration::from_nanos(1)));
            assert!(signal.begin_force_close());
        }
        assert!(lab.run_until_idle() < 2048);
        assert_eq!(cleanup.load(Ordering::SeqCst), 2);
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        assert_eq!(in_flight.load(Ordering::SeqCst), 1);
        assert!(result.lock().is_none());
        assert_eq!(lab.run_until_idle(), 0, "cancelled drain really parks");
        release_body.send_blocking(()).unwrap();
        assert!(lab.run_until_idle() < 2048);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert_eq!(cancelled.load(Ordering::SeqCst), 1);
        assert!(
            result.lock().is_none(),
            "body join cannot substitute for descendant close"
        );
        assert_eq!(in_flight.load(Ordering::SeqCst), 1);
        assert_eq!(lab.run_until_idle(), 0);
        release_child.send_blocking(()).unwrap();
        assert!(lab.run_until_idle() < 2048);
        if parent_cancel {
            assert!(
                matches!(join.try_join(), Err(JoinError::Cancelled(reason)) if reason.kind == CancelKind::User)
            );
        } else {
            assert_eq!(join.try_join(), Ok(Some(())));
        }
        let completed = result.lock().take().unwrap();
        assert!(matches!(
            completed.hop,
            ServerHopOutcome::Ok(H2DispatchResponse::Buffered(_))
        ));
        assert!(matches!(
            completed.task_outcome,
            Some(Err(JoinError::Cancelled(_)))
        ));
        assert!(!completed.idle_expired);
        assert_eq!(in_flight.load(Ordering::SeqCst), 0);
        assert_eq!(lab.state.live_task_count(), 0);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert_owned_h2_terminal_trace(&lab.state.trace_handle().snapshot(), &body, owner);
        finish_owned_h2_lab(&mut lab, root);
    }

    fn assert_owned_h2_terminal_trace(
        events: &[crate::trace::TraceEvent],
        body: &Cx,
        owner: crate::types::TaskId,
    ) {
        use crate::trace::{TraceData, TraceEventKind};
        let terminal = |task| {
            events.iter().filter(|event| {
            event.kind == TraceEventKind::Complete
                && matches!(event.data, TraceData::Task { task: actual, .. } if actual == task)
        }).collect::<Vec<_>>()
        };
        let body_terminal = terminal(body.task_id());
        let owner_terminal = terminal(owner);
        assert_eq!(body_terminal.len(), 1);
        assert_eq!(owner_terminal.len(), 1);
        assert!(
            matches!(body_terminal[0].data, TraceData::Task { region, .. } if region == body.region_id())
        );
        let closed = events.iter().filter(|event| {
            event.kind == TraceEventKind::RegionCloseComplete
                && matches!(event.data, TraceData::Region { region, .. } if region == body.region_id())
        }).collect::<Vec<_>>();
        assert_eq!(closed.len(), 1);
        assert!(body_terminal[0].seq < closed[0].seq);
        assert!(closed[0].seq < owner_terminal[0].seq);
    }

    #[test]
    fn owned_h2_request_shutdown_during_admission_never_starts_factory() {
        use crate::lab::{LabConfig, LabRuntime};
        let mut lab = LabRuntime::new(LabConfig::new(0x36_200).max_steps(1024));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let signal = ShutdownSignal::new();
        let task_signal = signal.clone();
        let invoked = Arc::new(AtomicUsize::new(0));
        let called = Arc::clone(&invoked);
        let (owner, mut join) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().unwrap();
                let mut hop = Box::pin(run_owned_h2_hop(
                    &cx,
                    &task_signal,
                    owned_hop_config(),
                    move || async move {
                        called.fetch_add(1, Ordering::SeqCst);
                        H2DispatchResponse::Buffered(
                            Response::new(200, "OK", b"forbidden".to_vec()).into_h2_response(),
                        )
                    },
                ));
                std::future::poll_fn(|poll_cx| {
                    assert!(
                        hop.as_mut().poll(poll_cx).is_pending(),
                        "actual opening must await scheduler admission"
                    );
                    Poll::Ready(())
                })
                .await;
                assert!(task_signal.begin_drain(Duration::from_nanos(1)));
                assert!(task_signal.begin_force_close());
                let completed = hop.await.unwrap();
                assert!(matches!(completed.hop, ServerHopOutcome::Cancelled));
                assert!(completed.task_outcome.is_none());
            })
            .unwrap();
        lab.scheduler.lock().schedule(owner, 0);
        assert!(lab.run_until_idle() < 1024);
        assert_eq!(join.try_join(), Ok(Some(())));
        assert_eq!(invoked.load(Ordering::SeqCst), 0);
        assert_eq!(lab.state.live_task_count(), 0);
        let events = lab.state.trace_handle().snapshot();
        let opened = events
            .iter()
            .filter(|event| event.kind == crate::trace::TraceEventKind::RegionCreated)
            .count();
        let closed = events
            .iter()
            .filter(|event| event.kind == crate::trace::TraceEventKind::RegionCloseComplete)
            .count();
        assert_eq!(
            opened, 2,
            "one actual root and one admitted empty request region"
        );
        assert_eq!(closed, 1, "the admitted request is actually closed");
        finish_owned_h2_lab(&mut lab, root);
    }

    #[test]
    fn owned_h2_request_deadline_and_idle_expiry_retire_only_after_grace() {
        use crate::lab::{LabConfig, LabRuntime};
        for idle in [false, true] {
            let mut lab =
                LabRuntime::new(LabConfig::new(0x36_300 + u64::from(idle)).max_steps(1024));
            let root = lab.state.create_root_region(Budget::INFINITE);
            let signal = ShutdownSignal::new();
            let dropped = Arc::new(AtomicUsize::new(0));
            let retired = Arc::clone(&dropped);
            let cancelled = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&cancelled);
            let output = Arc::new(parking_lot::Mutex::new(None));
            let returned = Arc::clone(&output);
            let mut config = owned_hop_config();
            config.drain_grace = Duration::from_nanos(10);
            if idle {
                config.idle_timeout = Some(Duration::from_nanos(100));
            } else {
                config.budget = config.budget.with_deadline(Time::from_nanos(100));
            }
            let (owner, mut join) = lab
                .state
                .create_task(root, Budget::INFINITE, async move {
                    let cx = Cx::current().unwrap();
                    let completed = run_owned_h2_hop(&cx, &signal, config, move || async move {
                        let _drop = OwnedBodyDrop {
                            cx: Cx::current().unwrap(),
                            dropped: retired,
                            cancelled: observed,
                        };
                        std::future::pending::<H2DispatchResponse>().await
                    })
                    .await
                    .unwrap();
                    *returned.lock() = Some(completed);
                })
                .unwrap();
            lab.scheduler.lock().schedule(owner, 0);
            assert!(lab.run_until_idle() < 1024);
            assert_eq!(dropped.load(Ordering::SeqCst), 0);
            lab.advance_time_to(Time::from_nanos(100));
            assert!(lab.state.timer_driver_handle().unwrap().process_timers() > 0);
            assert!(lab.run_until_idle() < 1024);
            assert!(output.lock().is_none());
            assert_eq!(
                dropped.load(Ordering::SeqCst),
                0,
                "expiry requests cancellation before retiring the body"
            );
            assert_eq!(lab.run_until_idle(), 0, "grace waits on its owned timer");
            lab.advance_time_to(Time::from_nanos(110));
            assert!(lab.state.timer_driver_handle().unwrap().process_timers() > 0);
            assert!(lab.run_until_idle() < 1024);
            assert_eq!(join.try_join(), Ok(Some(())));
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
            assert_eq!(cancelled.load(Ordering::SeqCst), 1);
            let completed = output.lock().take().unwrap();
            assert_eq!(completed.idle_expired, idle);
            assert!(matches!(
                completed.task_outcome,
                Some(Err(JoinError::Cancelled(_)))
            ));
            if idle {
                assert!(matches!(completed.hop, ServerHopOutcome::ConnectionLost));
            } else {
                assert!(matches!(completed.hop, ServerHopOutcome::DeadlineExceeded));
            }
            assert_eq!(lab.state.live_task_count(), 0);
            assert!(
                lab.state
                    .timer_driver_handle()
                    .unwrap()
                    .next_deadline()
                    .is_none()
            );
            finish_owned_h2_lab(&mut lab, root);
        }
    }

    #[test]
    fn owned_h2_request_delayed_join_preserves_strict_idle_deadline_and_exact_boundary() {
        use crate::channel::oneshot;
        use crate::lab::{LabConfig, LabRuntime};

        for completed_at in [100u64, 101] {
            let mut lab = LabRuntime::new(LabConfig::new(0x36_400 + completed_at).max_steps(2048));
            let root = lab.state.create_root_region(Budget::INFINITE);
            let signal = ShutdownSignal::new();
            let allow_coordinator = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let gate = Arc::clone(&allow_coordinator);
            let blocked_polls = Arc::new(AtomicUsize::new(0));
            let blocked = Arc::clone(&blocked_polls);
            let coordinator_waker = Arc::new(parking_lot::Mutex::new(None::<std::task::Waker>));
            let waiter = Arc::clone(&coordinator_waker);
            let body_cx = Arc::new(parking_lot::Mutex::new(None::<Cx>));
            let identity = Arc::clone(&body_cx);
            let dropped = Arc::new(AtomicUsize::new(0));
            let retired = Arc::clone(&dropped);
            let cancelled = Arc::new(AtomicUsize::new(0));
            let cancelled_body = Arc::clone(&cancelled);
            let in_flight = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&in_flight);
            let published = Arc::new(parking_lot::Mutex::new(None));
            let result = Arc::clone(&published);
            let (release, mut body_wait) = oneshot::channel::<()>();
            let mut config = owned_hop_config();
            config.idle_timeout = Some(Duration::from_nanos(100));
            let (owner, mut join) = lab
                .state
                .create_task(root, Budget::INFINITE, async move {
                    let cx = Cx::current().unwrap();
                    let _guard = InFlightRequestGuard::acquire(Some(&counter));
                    let mut hop =
                        Box::pin(run_owned_h2_hop(&cx, &signal, config, move || async move {
                            let body = Cx::current().expect("actual admitted body");
                            *identity.lock() = Some(body.clone());
                            let _drop = OwnedBodyDrop {
                                cx: body.clone(),
                                dropped: retired,
                                cancelled: cancelled_body,
                            };
                            body_wait.recv_uninterruptible().await.unwrap();
                            assert_eq!(body.now(), Time::from_nanos(completed_at));
                            H2DispatchResponse::Buffered(
                                Response::new(200, "OK", b"completed body".to_vec())
                                    .into_h2_response(),
                            )
                        }));
                    let completed = std::future::poll_fn(|poll_cx| {
                        if !gate.load(Ordering::SeqCst) {
                            *waiter.lock() = Some(poll_cx.waker().clone());
                            blocked.fetch_add(1, Ordering::SeqCst);
                            return Poll::Pending;
                        }
                        hop.as_mut().poll(poll_cx)
                    })
                    .await
                    .unwrap();
                    *result.lock() = Some(completed);
                })
                .unwrap();
            lab.scheduler.lock().schedule(owner, 0);
            assert!(lab.run_until_idle() < 2048);
            let body = body_cx
                .lock()
                .clone()
                .expect("actual body reached its wait");
            assert_ne!(body.task_id(), owner);
            assert_ne!(body.region_id(), root);
            assert_eq!(
                lab.state.task(body.task_id()).unwrap().owner,
                body.region_id()
            );
            assert_eq!(lab.state.live_task_count(), 2);
            assert_eq!(in_flight.load(Ordering::SeqCst), 1);
            assert!(published.lock().is_none());

            // The real timer wakes the coordinator, but this owned test gate
            // deliberately withholds its next hop poll. The separately
            // scheduled body still runs and reaches its actual terminal.
            allow_coordinator.store(false, Ordering::SeqCst);
            lab.advance_time_to(Time::from_nanos(completed_at));
            assert!(lab.state.timer_driver_handle().unwrap().process_timers() > 0);
            assert!(lab.run_until_idle() < 2048);
            assert!(blocked_polls.load(Ordering::SeqCst) > 0);
            assert_eq!(dropped.load(Ordering::SeqCst), 0);
            release.send_blocking(()).unwrap();
            assert!(lab.run_until_idle() < 2048);
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
            assert_eq!(cancelled.load(Ordering::SeqCst), 0);
            assert_eq!(
                lab.state.live_task_count(),
                1,
                "only the held coordinator is live"
            );
            assert_eq!(
                lab.state.regions_len(),
                2,
                "request region remains owned before join"
            );
            assert!(published.lock().is_none());
            assert_eq!(in_flight.load(Ordering::SeqCst), 1);
            assert_eq!(join.try_join(), Ok(None));
            let before = lab.state.trace_handle().snapshot();
            assert_eq!(
                before
                    .iter()
                    .filter(|event| event.kind == crate::trace::TraceEventKind::Complete
                        && matches!(event.data, crate::trace::TraceData::Task { task, region }
                    if task == body.task_id() && region == body.region_id()))
                    .count(),
                1
            );
            assert!(!before.iter().any(|event|
                event.kind == crate::trace::TraceEventKind::Complete &&
                matches!(event.data, crate::trace::TraceData::Task { task, .. } if task == owner)));

            allow_coordinator.store(true, Ordering::SeqCst);
            let wake = coordinator_waker
                .lock()
                .take()
                .expect("actual registered coordinator waiter");
            wake.wake();
            assert!(lab.run_until_idle() < 2048);
            assert_eq!(join.try_join(), Ok(Some(())));
            let completed = published.lock().take().unwrap();
            assert_eq!(
                completed.idle_expired,
                completed_at > 100,
                "strict overdue must reject; exactly at the boundary ready work wins"
            );
            assert!(matches!(completed.hop,
                ServerHopOutcome::Ok(H2DispatchResponse::Buffered(response))
                    if response.response.body.as_slice() == b"completed body"));
            assert!(
                matches!(completed.task_outcome, Some(Ok(()))),
                "late join cannot fabricate cancellation of an already completed body"
            );
            assert_eq!(cancelled.load(Ordering::SeqCst), 0);
            assert_eq!(in_flight.load(Ordering::SeqCst), 0);
            assert_owned_h2_terminal_trace(&lab.state.trace_handle().snapshot(), &body, owner);
            finish_owned_h2_lab(&mut lab, root);
        }
    }

    thread_local! {
        static H2_LISTENER_TEST_NOW: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    fn set_h2_listener_test_time(time: Time) {
        H2_LISTENER_TEST_NOW.with(|now| now.set(time.as_nanos()));
    }

    fn h2_listener_test_time() -> Time {
        H2_LISTENER_TEST_NOW.with(|now| Time::from_nanos(now.get()))
    }

    #[test]
    fn h2spec_request_content_length_matches_assembled_data() {
        for declared in [
            "0",
            "2",
            "4",
            "-3",
            "+3",
            " 3",
            "3,3",
            "",
            "18446744073709551616",
        ] {
            let result = request_from_h2_parts(
                request_block(&[("content-length", declared)]),
                b"abc".to_vec(),
                Vec::new(),
                None,
            );
            assert!(result.is_err(), "accepted malformed length {declared:?}");
        }
        let result = request_from_h2_parts(
            request_block(&[("content-length", "3")]),
            b"abc".to_vec(),
            vec![Header::new("x-checksum", "yes")],
            None,
        )
        .unwrap();
        assert_eq!(result.body, b"abc");
        assert!(
            request_from_h2_parts(
                request_block(&[("content-length", "3"), ("content-length", "4")]),
                b"abc".to_vec(),
                Vec::new(),
                None,
            )
            .is_err()
        );
        assert!(
            request_from_h2_parts(
                request_block(&[("content-length", "0")]),
                Vec::new(),
                Vec::new(),
                None,
            )
            .is_ok()
        );
    }

    fn request_block(extra: &[(&str, &str)]) -> Vec<Header> {
        let mut headers = vec![
            Header::new(":method", "GET"),
            Header::new(":scheme", "https"),
            Header::new(":path", "/widgets?q=1"),
            Header::new(":authority", "example.com:8443"),
        ];
        for (name, value) in extra {
            headers.push(Header::new(*name, *value));
        }
        headers
    }

    fn encode_hpack_test_headers(headers: &[(&str, &str)]) -> crate::bytes::Bytes {
        let mut encoder = crate::http::h2::hpack::Encoder::new();
        let mut encoded = crate::bytes::BytesMut::new();
        let headers = headers
            .iter()
            .map(|(name, value)| Header::new(*name, *value))
            .collect::<Vec<_>>();
        encoder.encode(&headers, &mut encoded);
        encoded.freeze()
    }

    fn expect_settings_ack(conn: &mut Connection) {
        match conn.next_frame().expect("SETTINGS ACK should be queued") {
            Frame::Settings(settings) => assert!(settings.ack, "expected SETTINGS ACK"),
            other => panic!("expected SETTINGS ACK, got {other:?}"),
        }
    }

    async fn panicking_h2_handler(_request: Request) -> H2DispatchResponse {
        panic!("handler exploded")
    }

    fn establish_h2_response_stream(conn: &mut Connection, stream_id: u32, path: &str) {
        let request_headers = encode_hpack_test_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", path),
            (":authority", "produced.example"),
        ]);
        let received = conn
            .process_frame(Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
                stream_id,
                request_headers,
                true,
                true,
            )))
            .expect("request HEADERS accepted");
        assert!(matches!(
            received,
            Some(ReceivedFrame::Headers {
                stream_id: received_stream_id,
                ..
            }) if received_stream_id == stream_id
        ));
    }

    #[test]
    fn body_diagnostic_h2_producer_outcomes_preserve_terminal_causes() {
        assert_eq!(
            h2_producer_outcome_diagnostic(Http2ProducerOutcome::Failed),
            Some((
                "ASUP-E510",
                "response producer returned an error or panicked"
            ))
        );
        assert_eq!(
            h2_producer_outcome_diagnostic(Http2ProducerOutcome::DeadlineExceeded),
            Some((
                "ASUP-E501",
                "response producer exhausted its request-region deadline"
            ))
        );
        assert_eq!(
            h2_producer_outcome_diagnostic(Http2ProducerOutcome::ConnectionLost),
            Some(("ASUP-E509", "response producer lost its client connection"))
        );
        assert_eq!(
            h2_producer_outcome_diagnostic(Http2ProducerOutcome::Cancelled),
            None
        );
    }

    #[test]
    fn body_diagnostic_cancelled_outgoing_body_uses_authoritative_hop_cause() {
        crate::test_utils::run_test(|| async {
            for (kind, expected) in [
                (
                    crate::types::CancelKind::Timeout,
                    Http2ProducerOutcome::DeadlineExceeded,
                ),
                (
                    crate::types::CancelKind::ParentCancelled,
                    Http2ProducerOutcome::Cancelled,
                ),
            ] {
                let producer_cx = Cx::for_testing();
                let (inner, mut body) =
                    OutgoingBody::channel_with_capacity(&producer_cx, BodyKind::Chunked, 1);
                let _sender = Http2BodySender {
                    inner,
                    max_frame_bytes: NonZeroUsize::new(8).expect("non-zero frame limit"),
                    terminal: Http2ProducerTerminal::Open,
                };
                producer_cx.cancel_with(kind, Some("causal producer cancellation test"));

                let error = std::future::poll_fn(|task_cx| Pin::new(&mut body).poll_frame(task_cx))
                    .await
                    .expect("cancelled body yields a terminal error")
                    .expect_err("cancelled body frame is not clean EOF");
                assert!(matches!(error, HttpError::BodyCancelled));
                assert_eq!(
                    classify_h2_producer_hop(Some(ServerHopOutcome::Ok(Err(error))), &producer_cx,),
                    expected
                );
            }
        });
    }

    #[test]
    fn body_diagnostic_peer_reset_survives_dispatch_to_produced_start_race() {
        let mut dispatched = HashSet::from([1]);
        let mut peer_reset_before_response = HashSet::new();

        assert!(mark_h2_peer_reset_before_response(
            &mut dispatched,
            &mut peer_reset_before_response,
            1,
        ));
        assert!(!dispatched.contains(&1));
        assert!(peer_reset_before_response.remove(&1));
        assert!(peer_reset_before_response.is_empty());
        assert!(!mark_h2_peer_reset_before_response(
            &mut dispatched,
            &mut peer_reset_before_response,
            1,
        ));
    }

    #[test]
    fn body_diagnostic_h2_write_failures_preserve_transport_vs_encoder_cause() {
        assert_eq!(
            h2_pump_failure_diagnostic(&H2PumpWriteError::Transport(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "peer closed",
            ))),
            Some(WebBodyDiagnostic::ClientAbort)
        );
        assert_eq!(
            h2_pump_failure_diagnostic(&H2PumpWriteError::Encode(H2Error::stream(
                1,
                ErrorCode::InternalError,
                "invalid local response frame",
            ))),
            Some(WebBodyDiagnostic::ResponseProducerFailure)
        );
        assert_eq!(
            h2_pump_failure_diagnostic(&H2PumpWriteError::Encode(H2Error::connection(
                ErrorCode::InternalError,
                "invalid local connection frame",
            ))),
            None
        );
    }

    #[test]
    fn produced_sender_rejects_oversized_data_before_channel_commit() {
        crate::test_utils::run_test(|| async {
            let cx = Cx::current().expect("test runtime installs Cx");
            let (inner, mut body) = OutgoingBody::channel_with_capacity(&cx, BodyKind::Chunked, 1);
            let mut sender = Http2BodySender {
                inner,
                max_frame_bytes: NonZeroUsize::new(3).expect("non-zero limit"),
                terminal: Http2ProducerTerminal::Open,
            };

            let error = sender
                .send_bytes(&cx, crate::bytes::Bytes::from_static(b"four"))
                .await
                .expect_err("oversized DATA must fail before queueing");
            assert!(matches!(
                error,
                HttpError::BodyTooLargeDetailed {
                    actual: 4,
                    limit: 3
                }
            ));
            assert_eq!(sender.total_bytes(), 0);

            std::future::poll_fn(|task_cx| {
                assert!(matches!(
                    Pin::new(&mut body).poll_frame(task_cx),
                    Poll::Pending
                ));
                Poll::Ready(())
            })
            .await;
        });
    }

    #[test]
    fn produced_sender_finish_preserves_trailers_terminal() {
        crate::test_utils::run_test(|| async {
            let cx = Cx::current().expect("test runtime installs Cx");
            let (inner, mut body) = OutgoingBody::channel_with_capacity(&cx, BodyKind::Chunked, 1);
            let mut sender = Http2BodySender {
                inner,
                max_frame_bytes: NonZeroUsize::new(8).expect("non-zero limit"),
                terminal: Http2ProducerTerminal::Open,
            };
            let mut trailers = HeaderMap::new();
            trailers.insert(
                crate::http::body::HeaderName::from_static("x-end"),
                crate::http::body::HeaderValue::from_static("true"),
            );

            sender
                .send_trailers(&cx, trailers)
                .await
                .expect("trailers finish the channel");
            sender
                .finish(&cx)
                .expect("finish remains idempotent after trailers");
            assert_eq!(sender.terminal, Http2ProducerTerminal::Trailers);

            let frame = std::future::poll_fn(|task_cx| Pin::new(&mut body).poll_frame(task_cx))
                .await
                .expect("trailers frame")
                .expect("valid trailers frame");
            assert!(matches!(frame, BodyFrame::Trailers(_)));
            assert!(
                std::future::poll_fn(|task_cx| Pin::new(&mut body).poll_frame(task_cx))
                    .await
                    .is_none(),
                "trailers must be the sole terminal frame"
            );
        });
    }

    #[test]
    fn produced_cancellation_guard_cancels_when_driver_drops_ownership() {
        let producer_cx: Cx = Cx::for_testing();
        assert!(!producer_cx.is_cancel_requested());
        drop(ProducedCancellationGuard::new(producer_cx.clone()));
        assert!(producer_cx.is_cancel_requested());
    }

    #[test]
    fn produced_cancellation_retains_in_flight_until_producer_owner_exits() {
        let channel_cx: Cx = Cx::for_testing();
        let producer_cx: Cx = Cx::for_testing();
        let (_sender, body) =
            OutgoingBody::channel_with_capacity(&channel_cx, BodyKind::Chunked, 1);
        let in_flight = Arc::new(AtomicUsize::new(0));
        let transport_guard = Arc::new(InFlightRequestGuard::acquire(Some(&in_flight)));
        let producer_guard = Arc::clone(&transport_guard);
        let mut produced_bodies = BTreeMap::from([(
            1,
            ActiveProducedBody {
                body,
                pending_initial_response: None,
                cancellation: ProducedCancellationGuard::new(producer_cx),
                guard: Some(transport_guard),
                producer_outcome: None,
                emitted_bytes: 0,
                body_eof: false,
                pending_trailers: None,
                failure_drain_deadline: None,
                receive: ProducedReceive::Live,
            },
        )]);
        assert_eq!(in_flight.load(Ordering::Acquire), 1);

        cancel_produced_body(&mut produced_bodies, 1, "test transport cancellation");
        assert!(produced_bodies.is_empty());
        assert_eq!(
            in_flight.load(Ordering::Acquire),
            1,
            "transport cancellation cannot report quiescence while producer ownership remains"
        );

        drop(producer_guard);
        assert_eq!(
            in_flight.load(Ordering::Acquire),
            0,
            "the final producer-task owner releases in-flight accounting"
        );
    }

    #[test]
    fn produced_factory_panic_is_reported_after_start_instead_of_escaping() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime.block_on(async move {
            let cx = Cx::current().expect("runtime installs Cx for block_on");
            let mut conn = Connection::server(Settings::default());
            let (resp_tx, mut resp_rx) = mpsc::channel::<FunnelItem>(RESPONSE_FUNNEL_CAPACITY);
            let shutdown_signal = ShutdownSignal::new();
            let in_flight = Arc::new(AtomicUsize::new(0));
            let handler = Arc::new(|_req: Request| async move {
                H2DispatchResponse::Produced(Http2ProducedPlan {
                    response: Response::new(200, "OK", Vec::new()),
                    frame_capacity: NonZeroUsize::MIN,
                    max_frame_bytes: NonZeroUsize::new(8).expect("non-zero limit"),
                    deferred_initial_headers: false,
                    producer: Box::new(|_, _| panic!("producer factory exploded")),
                })
            });

            let _coordinator = dispatch_h2_request(
                &mut conn,
                1,
                request_block(&[]),
                Vec::new(),
                Vec::new(),
                None,
                &handler,
                &resp_tx,
                &shutdown_signal,
                &in_flight,
                &cx,
                &HostPolicy::allow_list(vec!["example.com".to_owned()]),
                None,
                None,
                Duration::from_millis(500),
                None,
                false,
                usize::MAX,
            ).expect("dispatch coordinator");

            let start = resp_rx
                .recv(&cx)
                .await
                .expect("validated head must be funneled before producer polling");
            assert!(matches!(
                start,
                FunnelItem::ProducedStart { stream_id: 1, .. }
            ));
            let done = resp_rx
                .recv(&cx)
                .await
                .expect("factory panic must become a terminal producer outcome");
            assert!(matches!(
                done,
                FunnelItem::ProducedDone {
                    stream_id: 1,
                    outcome: Http2ProducerOutcome::Failed,
                }
            ));
            drop(start);
        });
    }

    #[test]
    fn produced_head_preserves_authored_status_without_starting_factory() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime.block_on(async move {
            let cx = Cx::current().expect("runtime installs Cx for block_on");
            let mut conn = Connection::server(Settings::default());
            let (resp_tx, mut resp_rx) = mpsc::channel::<FunnelItem>(RESPONSE_FUNNEL_CAPACITY);
            let shutdown_signal = ShutdownSignal::new();
            let in_flight = Arc::new(AtomicUsize::new(0));
            let factory_invoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let factory_invoked_for_handler = Arc::clone(&factory_invoked);
            let handler = Arc::new(move |_req: Request| {
                let factory_invoked = Arc::clone(&factory_invoked_for_handler);
                async move {
                    H2DispatchResponse::Produced(Http2ProducedPlan {
                        response: Response::new(201, "Created", Vec::new())
                            .with_header("x-produced", "head"),
                        frame_capacity: NonZeroUsize::MIN,
                        max_frame_bytes: NonZeroUsize::new(8).expect("non-zero limit"),
                        deferred_initial_headers: false,
                        producer: Box::new(move |_producer_cx, sender| {
                            factory_invoked.store(true, Ordering::SeqCst);
                            Box::pin(async move { Ok(sender) })
                        }),
                    })
                }
            });
            let headers = vec![
                Header::new(":method", "HEAD"),
                Header::new(":scheme", "https"),
                Header::new(":path", "/produced-head"),
                Header::new(":authority", "example.com"),
            ];

            let _coordinator = dispatch_h2_request(
                &mut conn,
                1,
                headers,
                Vec::new(),
                Vec::new(),
                None,
                &handler,
                &resp_tx,
                &shutdown_signal,
                &in_flight,
                &cx,
                &HostPolicy::allow_list(vec!["example.com".to_owned()]),
                None,
                None,
                Duration::from_millis(500),
                None,
                false,
                usize::MAX,
            ).expect("dispatch coordinator");

            let item = resp_rx
                .recv(&cx)
                .await
                .expect("HEAD response must be funneled");
            let FunnelItem::Response {
                response,
                guard,
                suppress_response_body,
                ..
            } = item
            else {
                panic!("HEAD must use the body-suppressed buffered path");
            };
            assert_eq!(response.response.status, 201);
            assert!(suppress_response_body);
            assert!(!factory_invoked.load(Ordering::SeqCst));
            assert!(
                resp_rx.try_recv().is_err(),
                "HEAD must not start a producer"
            );
            drop(guard);
        });
    }

    #[test]
    fn produced_body_is_not_polled_until_stream_credit_arrives() {
        crate::test_utils::run_test(|| async {
            let cx = Cx::current().expect("test runtime installs Cx");
            let mut conn = Connection::server(Settings::default());
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                vec![crate::http::h2::frame::Setting::InitialWindowSize(0)],
            )))
            .expect("zero initial stream window accepted");
            expect_settings_ack(&mut conn);
            establish_h2_response_stream(&mut conn, 1, "/credit");
            assert_eq!(conn.available_send_capacity(1), 0);

            let (inner, body) = OutgoingBody::channel_with_capacity(&cx, BodyKind::Chunked, 1);
            let mut sender = Http2BodySender {
                inner,
                max_frame_bytes: NonZeroUsize::new(8).expect("non-zero limit"),
                terminal: Http2ProducerTerminal::Open,
            };
            sender
                .send_bytes(&cx, crate::bytes::Bytes::from_static(b"abc"))
                .await
                .expect("bounded DATA queues in producer channel");
            sender.finish(&cx).expect("producer finishes");

            let mut produced_bodies = BTreeMap::from([(
                1,
                ActiveProducedBody {
                    body,
                    pending_initial_response: None,
                    cancellation: ProducedCancellationGuard::new(Cx::for_testing()),
                    guard: Some(Arc::new(InFlightRequestGuard::acquire(None))),
                    producer_outcome: Some(Http2ProducerOutcome::Finished {
                        total_bytes: sender.total_bytes(),
                        terminal: sender.terminal,
                    }),
                    emitted_bytes: 0,
                    body_eof: false,
                    pending_trailers: None,
                    failure_drain_deadline: None,
                    receive: ProducedReceive::Live,
                },
            )]);
            let mut poll_after = None;
            std::future::poll_fn(|task_cx| {
                assert!(matches!(
                    poll_produced_body_event(&conn, &mut produced_bodies, &mut poll_after, task_cx),
                    Poll::Pending
                ));
                Poll::Ready(())
            })
            .await;

            conn.process_frame(Frame::WindowUpdate(
                crate::http::h2::frame::WindowUpdateFrame::new(1, 3),
            ))
            .expect("stream WINDOW_UPDATE accepted");
            let event = std::future::poll_fn(|task_cx| {
                poll_produced_body_event(&conn, &mut produced_bodies, &mut poll_after, task_cx)
            })
            .await;
            let ProducedBodyEvent::Frame {
                stream_id: 1,
                frame: Ok(BodyFrame::Data(data)),
            } = event
            else {
                panic!("expected one DATA frame after credit arrived");
            };
            assert_eq!(data.get_ref().as_ref(), b"abc");
        });
    }

    #[test]
    fn produced_body_credit_observes_connection_window_exhaustion() {
        let mut conn = Connection::server(Settings::default());
        conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
            vec![crate::http::h2::frame::Setting::InitialWindowSize(100_000)],
        )))
        .expect("larger peer stream window accepted");
        expect_settings_ack(&mut conn);
        establish_h2_response_stream(&mut conn, 1, "/connection-credit");

        conn.send_data(1, crate::bytes::Bytes::from(vec![0_u8; 70_000]), false)
            .expect("DATA queues beyond the connection window");
        let mut emitted = 0_usize;
        while let Some(frame) = conn.next_frame() {
            let Frame::Data(data) = frame else {
                panic!("expected only DATA while draining connection credit");
            };
            emitted += data.data.len();
        }
        assert_eq!(emitted, 65_535);
        assert_eq!(conn.available_send_capacity(1), 0);

        conn.process_frame(Frame::WindowUpdate(
            crate::http::h2::frame::WindowUpdateFrame::new(1, 32),
        ))
        .expect("stream credit update accepted");
        assert_eq!(
            conn.available_send_capacity(1),
            0,
            "stream credit cannot bypass an exhausted connection window"
        );

        conn.process_frame(Frame::WindowUpdate(
            crate::http::h2::frame::WindowUpdateFrame::new(0, 3),
        ))
        .expect("connection credit update accepted");
        assert_eq!(conn.available_send_capacity(1), 3);
    }

    #[test]
    fn a_ready_producer_does_not_hold_off_the_peers_frames() {
        // br-asupersync-dx72q4 F4: the driver polled produced bodies before
        // the transport, so while a producer had frames ready the peer's
        // frames waited until the stream ran out of send credit.
        crate::test_utils::run_test(|| async {
            use crate::io::AsyncWriteExt as _;

            let cx = Cx::current().expect("test runtime installs Cx");
            let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
            let addr = tcp.local_addr().expect("listener address");
            let mut client = TcpStream::connect(addr).await.expect("connect");
            let (server, _) = tcp.accept().await.expect("accept");
            let mut framed = listener_framed(
                H2Transport::Plain(H2Socket {
                    stream: server,
                    bytes_written: 0,
                }),
                crate::http::h2::frame::DEFAULT_MAX_FRAME_SIZE,
            );
            // Two PINGs in one write: once the first is read, the second has
            // arrived, so the driver can read it whenever it polls.
            let ping = [0, 0, 8, 0x6, 0, 0, 0, 0, 0, 7, 7, 7, 7, 7, 7, 7, 7];
            client
                .write_all(&[ping, ping].concat())
                .await
                .expect("PINGs written");
            let first =
                std::future::poll_fn(|task_cx| Pin::new(&mut framed).poll_next(task_cx)).await;
            assert!(
                matches!(first, Some(Ok(DecodedFrame::Frame(Frame::Ping(_))))),
                "expected the first PING, got {first:?}",
            );

            let mut conn = Connection::server(Settings::default());
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                Vec::new(),
            )))
            .expect("initial settings accepted");
            expect_settings_ack(&mut conn);
            establish_h2_response_stream(&mut conn, 1, "/ready-producer");

            let (inner, body) = OutgoingBody::channel_with_capacity(&cx, BodyKind::Chunked, 2);
            let mut sender = Http2BodySender {
                inner,
                max_frame_bytes: NonZeroUsize::new(8).expect("non-zero limit"),
                terminal: Http2ProducerTerminal::Open,
            };
            for chunk in [b"a", b"b"] {
                sender
                    .send_bytes(&cx, crate::bytes::Bytes::from_static(chunk))
                    .await
                    .expect("DATA queues in the producer channel");
            }
            let mut produced_bodies = BTreeMap::from([(
                1,
                ActiveProducedBody {
                    body,
                    pending_initial_response: None,
                    cancellation: ProducedCancellationGuard::new(Cx::for_testing()),
                    guard: Some(Arc::new(InFlightRequestGuard::acquire(None))),
                    producer_outcome: None,
                    emitted_bytes: 0,
                    body_eof: false,
                    pending_trailers: None,
                    failure_drain_deadline: None,
                    receive: ProducedReceive::Live,
                },
            )]);

            let (_funnel_tx, mut resp_rx) = mpsc::channel::<FunnelItem>(1);
            let signal = ShutdownSignal::new();
            let mut request_owners = H2RequestOwners::new(&cx)
                .await
                .expect("request owners open");
            #[cfg(feature = "http2-streaming")]
            let mut incoming: Option<StreamingRequests> = None;
            let mut poll_after = None;
            let mut read_turn = false;
            let mut order = Vec::new();
            for _ in 0..3 {
                let event = next_driver_event(
                    &mut framed,
                    &mut resp_rx,
                    #[cfg(not(feature = "http2-streaming"))]
                    &conn,
                    #[cfg(feature = "http2-streaming")]
                    &mut conn,
                    #[cfg(feature = "http2-streaming")]
                    &mut incoming,
                    &mut produced_bodies,
                    &mut poll_after,
                    &mut read_turn,
                    &cx,
                    &signal,
                    false,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    &mut request_owners,
                )
                .await;
                order.push(match event {
                    DriverEvent::ProducedBody(ProducedBodyEvent::Frame {
                        stream_id: 1,
                        frame: Ok(BodyFrame::Data(_)),
                    }) => "DATA",
                    DriverEvent::Frame(Some(Ok(DecodedFrame::Frame(Frame::Ping(_))))) => "PING",
                    _ => "other",
                });
            }
            assert_eq!(order, ["DATA", "PING", "DATA"]);

            drop(sender);
            request_owners
                .close(CancelReason::user("test complete"))
                .await
                .expect("request owners close");
        });
    }

    #[test]
    fn produced_empty_eof_queues_one_terminal_frame_and_retains_guard() {
        crate::test_utils::run_test(|| async {
            let cx = Cx::current().expect("test runtime installs Cx");
            let mut conn = Connection::server(Settings::default());
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                Vec::new(),
            )))
            .expect("peer settings accepted");
            expect_settings_ack(&mut conn);
            establish_h2_response_stream(&mut conn, 1, "/empty");
            conn.send_headers(1, vec![Header::new(":status", "200")], false)
                .expect("produced response head queues");
            assert!(matches!(conn.next_frame(), Some(Frame::Headers(_))));

            let (mut sender, body) = OutgoingBody::channel_with_capacity(&cx, BodyKind::Chunked, 1);
            sender.finish(&cx).expect("empty producer finishes");
            let in_flight = Arc::new(AtomicUsize::new(0));
            let mut produced_bodies = BTreeMap::from([(
                1,
                ActiveProducedBody {
                    body,
                    pending_initial_response: None,
                    cancellation: ProducedCancellationGuard::new(Cx::for_testing()),
                    guard: Some(Arc::new(InFlightRequestGuard::acquire(Some(&in_flight)))),
                    producer_outcome: Some(Http2ProducerOutcome::Finished {
                        total_bytes: 0,
                        terminal: Http2ProducerTerminal::Finished,
                    }),
                    emitted_bytes: 0,
                    body_eof: false,
                    pending_trailers: None,
                    failure_drain_deadline: None,
                    receive: ProducedReceive::Live,
                },
            )]);
            let mut poll_after = None;
            let event = std::future::poll_fn(|task_cx| {
                poll_produced_body_event(&conn, &mut produced_bodies, &mut poll_after, task_cx)
            })
            .await;
            assert!(matches!(event, ProducedBodyEvent::Eof { stream_id: 1 }));
            produced_bodies
                .get_mut(&1)
                .expect("body remains active")
                .body_eof = true;

            let mut response_guards = HashMap::new();
            finalize_produced_body_if_ready(
                &mut conn,
                1,
                &mut produced_bodies,
                &mut response_guards,
            );
            assert!(produced_bodies.is_empty());
            assert_eq!(in_flight.load(Ordering::Acquire), 1);
            assert!(response_guards.contains_key(&1));
            match conn.next_frame().expect("terminal DATA queues") {
                Frame::Data(frame) => {
                    assert!(frame.data.is_empty());
                    assert!(frame.end_stream);
                }
                other => panic!("expected terminal DATA, got {other:?}"),
            }
            release_flushed_response_guards(&conn, &mut response_guards);
            assert!(response_guards.is_empty());
            assert_eq!(in_flight.load(Ordering::Acquire), 0);
            assert!(
                conn.next_frame().is_none(),
                "terminal framing is exactly once"
            );
        });
    }

    #[test]
    fn produced_trailers_queue_one_terminal_headers_frame_after_body_completion() {
        crate::test_utils::run_test(|| async {
            let cx = Cx::current().expect("test runtime installs Cx");
            let mut conn = Connection::server(Settings::default());
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                Vec::new(),
            )))
            .expect("peer settings accepted");
            expect_settings_ack(&mut conn);
            establish_h2_response_stream(&mut conn, 1, "/produced-trailers");
            conn.send_headers(1, vec![Header::new(":status", "200")], false)
                .expect("produced response head queues");
            assert!(matches!(conn.next_frame(), Some(Frame::Headers(_))));

            let (inner, body) = OutgoingBody::channel_with_capacity(&cx, BodyKind::Chunked, 1);
            let mut sender = Http2BodySender {
                inner,
                max_frame_bytes: NonZeroUsize::new(64).expect("non-zero limit"),
                terminal: Http2ProducerTerminal::Open,
            };
            let mut trailers = HeaderMap::new();
            trailers.insert(
                crate::http::body::HeaderName::from_static("x-final"),
                crate::http::body::HeaderValue::from_static("done"),
            );
            sender
                .send_trailers(&cx, trailers)
                .await
                .expect("trailers queue");
            sender
                .finish(&cx)
                .expect("finish after trailers is idempotent");

            let in_flight = Arc::new(AtomicUsize::new(0));
            let mut produced_bodies = BTreeMap::from([(
                1,
                ActiveProducedBody {
                    body,
                    pending_initial_response: None,
                    cancellation: ProducedCancellationGuard::new(Cx::for_testing()),
                    guard: Some(Arc::new(InFlightRequestGuard::acquire(Some(&in_flight)))),
                    producer_outcome: Some(Http2ProducerOutcome::Finished {
                        total_bytes: 0,
                        terminal: sender.terminal,
                    }),
                    emitted_bytes: 0,
                    body_eof: false,
                    pending_trailers: None,
                    failure_drain_deadline: None,
                    receive: ProducedReceive::Live,
                },
            )]);
            let mut poll_after = None;
            let event = std::future::poll_fn(|task_cx| {
                poll_produced_body_event(&conn, &mut produced_bodies, &mut poll_after, task_cx)
            })
            .await;
            let ProducedBodyEvent::Frame {
                stream_id: 1,
                frame: Ok(BodyFrame::Trailers(trailers)),
            } = event
            else {
                panic!("expected the produced trailing header map");
            };
            produced_bodies
                .get_mut(&1)
                .expect("body remains active until trailers queue")
                .pending_trailers = Some(trailers);

            let mut response_guards = HashMap::new();
            finalize_produced_body_if_ready(
                &mut conn,
                1,
                &mut produced_bodies,
                &mut response_guards,
            );
            assert!(produced_bodies.is_empty());
            assert_eq!(in_flight.load(Ordering::Acquire), 1);
            match conn.next_frame().expect("terminal trailing HEADERS queue") {
                Frame::Headers(headers) => {
                    assert_eq!(headers.stream_id, 1);
                    assert!(headers.end_stream);
                    let mut block = headers.header_block;
                    let decoded = crate::http::h2::HpackDecoder::new()
                        .decode(&mut block)
                        .expect("produced trailers decode");
                    assert_eq!(decoded, vec![Header::new("x-final", "done")]);
                }
                other => panic!("expected terminal trailing HEADERS, got {other:?}"),
            }
            release_flushed_response_guards(&conn, &mut response_guards);
            assert!(response_guards.is_empty());
            assert_eq!(in_flight.load(Ordering::Acquire), 0);
            assert!(
                conn.next_frame().is_none(),
                "trailers terminalize exactly once"
            );
        });
    }

    #[test]
    fn produced_trailers_committed_after_an_observed_cancellation_terminate_the_stream() {
        crate::test_utils::run_test(|| async {
            let mut conn = Connection::server(Settings::default());
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                Vec::new(),
            )))
            .expect("peer settings accepted");
            expect_settings_ack(&mut conn);
            establish_h2_response_stream(&mut conn, 1, "/cancelled-then-trailers");
            conn.send_headers(1, vec![Header::new(":status", "200")], false)
                .expect("produced response head queues");
            assert!(matches!(conn.next_frame(), Some(Frame::Headers(_))));

            let producer_cx: Cx = Cx::for_testing();
            let (inner, body) =
                OutgoingBody::channel_with_capacity(&producer_cx, BodyKind::Chunked, 1);
            let mut sender = Http2BodySender {
                inner,
                max_frame_bytes: NonZeroUsize::new(64).expect("non-zero limit"),
                terminal: Http2ProducerTerminal::Open,
            };
            let in_flight = Arc::new(AtomicUsize::new(0));
            let mut produced_bodies = BTreeMap::from([(
                1,
                ActiveProducedBody {
                    body,
                    pending_initial_response: None,
                    cancellation: ProducedCancellationGuard::new(Cx::for_testing()),
                    guard: Some(Arc::new(InFlightRequestGuard::acquire(Some(&in_flight)))),
                    producer_outcome: None,
                    emitted_bytes: 0,
                    body_eof: false,
                    pending_trailers: None,
                    failure_drain_deadline: None,
                    receive: ProducedReceive::Live,
                },
            )]);
            let mut poll_after = None;
            let mut response_guards = HashMap::new();

            // The listener polls between the producer's cancellation and its
            // masked terminal commit, as a gRPC status write does after the
            // service unwinds.
            producer_cx.cancel_fast(CancelKind::User);
            let event = std::future::poll_fn(|task_cx| {
                poll_produced_body_event(&conn, &mut produced_bodies, &mut poll_after, task_cx)
            })
            .await;
            assert!(matches!(
                event,
                ProducedBodyEvent::Frame {
                    stream_id: 1,
                    frame: Err(HttpError::BodyCancelled),
                }
            ));
            let state = produced_bodies.get_mut(&1).expect("body remains active");
            state.body_eof = true;
            state.receive = ProducedReceive::Cancelled;
            finalize_produced_body_if_ready(
                &mut conn,
                1,
                &mut produced_bodies,
                &mut response_guards,
            );
            assert!(
                produced_bodies.contains_key(&1),
                "no outcome yet: keep waiting"
            );

            let mut trailers = HeaderMap::new();
            trailers.insert(
                crate::http::body::HeaderName::from_static("grpc-status"),
                crate::http::body::HeaderValue::from_static("1"),
            );
            {
                let mut send = std::pin::pin!(sender.send_trailers(&producer_cx, trailers));
                let committed = std::future::poll_fn(|task| {
                    Poll::Ready(producer_cx.masked(|| send.as_mut().poll(task)))
                })
                .await;
                assert!(
                    matches!(committed, Poll::Ready(Ok(()))),
                    "masked trailers commit"
                );
            }
            produced_bodies
                .get_mut(&1)
                .expect("body remains active")
                .producer_outcome = Some(Http2ProducerOutcome::Finished {
                total_bytes: 0,
                terminal: sender.terminal,
            });
            finalize_produced_body_if_ready(
                &mut conn,
                1,
                &mut produced_bodies,
                &mut response_guards,
            );
            assert!(
                produced_bodies.contains_key(&1),
                "the stream stays open until its committed trailers are read"
            );

            let event = std::future::poll_fn(|task_cx| {
                poll_produced_body_event(&conn, &mut produced_bodies, &mut poll_after, task_cx)
            })
            .await;
            let ProducedBodyEvent::Frame {
                stream_id: 1,
                frame: Ok(BodyFrame::Trailers(trailers)),
            } = event
            else {
                panic!("the committed trailers must be read after the producer returned");
            };
            produced_bodies
                .get_mut(&1)
                .expect("body remains active until trailers queue")
                .pending_trailers = Some(trailers);
            finalize_produced_body_if_ready(
                &mut conn,
                1,
                &mut produced_bodies,
                &mut response_guards,
            );
            assert!(produced_bodies.is_empty());
            match conn.next_frame().expect("terminal trailing HEADERS queue") {
                Frame::Headers(headers) => {
                    assert!(headers.end_stream);
                    let mut block = headers.header_block;
                    let decoded = crate::http::h2::HpackDecoder::new()
                        .decode(&mut block)
                        .expect("produced trailers decode");
                    assert_eq!(decoded, vec![Header::new("grpc-status", "1")]);
                }
                other => panic!("expected terminal trailing HEADERS, got {other:?}"),
            }
            release_flushed_response_guards(&conn, &mut response_guards);
            assert_eq!(in_flight.load(Ordering::Acquire), 0);
        });
    }

    #[test]
    fn produced_trailers_the_producer_never_committed_reset_instead_of_waiting() {
        crate::test_utils::run_test(|| async {
            let mut conn = Connection::server(Settings::default());
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                Vec::new(),
            )))
            .expect("peer settings accepted");
            expect_settings_ack(&mut conn);
            establish_h2_response_stream(&mut conn, 1, "/claimed-trailers");
            conn.send_headers(1, vec![Header::new(":status", "200")], false)
                .expect("produced response head queues");
            assert!(matches!(conn.next_frame(), Some(Frame::Headers(_))));

            let producer_cx: Cx = Cx::for_testing();
            let (_sender, body) =
                OutgoingBody::channel_with_capacity(&producer_cx, BodyKind::Chunked, 1);
            producer_cx.cancel_fast(CancelKind::User);
            let in_flight = Arc::new(AtomicUsize::new(0));
            let mut produced_bodies = BTreeMap::from([(
                1,
                ActiveProducedBody {
                    body,
                    pending_initial_response: None,
                    cancellation: ProducedCancellationGuard::new(Cx::for_testing()),
                    guard: Some(Arc::new(InFlightRequestGuard::acquire(Some(&in_flight)))),
                    producer_outcome: Some(Http2ProducerOutcome::Finished {
                        total_bytes: 0,
                        terminal: Http2ProducerTerminal::Trailers,
                    }),
                    emitted_bytes: 0,
                    body_eof: true,
                    pending_trailers: None,
                    failure_drain_deadline: None,
                    receive: ProducedReceive::Cancelled,
                },
            )]);
            let mut poll_after = None;
            let mut response_guards = HashMap::new();
            finalize_produced_body_if_ready(
                &mut conn,
                1,
                &mut produced_bodies,
                &mut response_guards,
            );
            let event = std::future::poll_fn(|task_cx| {
                poll_produced_body_event(&conn, &mut produced_bodies, &mut poll_after, task_cx)
            })
            .await;
            assert!(matches!(event, ProducedBodyEvent::Eof { stream_id: 1 }));
            produced_bodies
                .get_mut(&1)
                .expect("body remains active")
                .body_eof = true;
            finalize_produced_body_if_ready(
                &mut conn,
                1,
                &mut produced_bodies,
                &mut response_guards,
            );
            assert!(
                produced_bodies.is_empty(),
                "a missing terminal frame must not wait forever"
            );
            assert!(
                matches!(conn.next_frame(), Some(Frame::RstStream(reset)) if reset.error_code == ErrorCode::InternalError),
                "the stream resets with INTERNAL_ERROR"
            );
            assert_eq!(in_flight.load(Ordering::Acquire), 0);
        });
    }

    #[test]
    fn stats_snapshot_records_accept_spawn_and_drain_counters() {
        let stats = Http2ListenerStats::new(h2_listener_test_time);

        set_h2_listener_test_time(Time::from_millis(321));
        stats.record_accepted();
        stats.record_transient_accept_error();
        stats.record_spawn_failure();
        stats.record_tls_handshake_rejection();
        stats.record_drain_started(3);
        stats.record_drain_escalated();
        stats.record_drain_hard_deadline();
        stats.record_drain_finished(&GracefulDrainReport {
            requests_at_drain_start: 3,
            requests_completed: 1,
            requests_stranded: 2,
            requests_at_escalation: Some(2),
            observations: 4,
            final_phase: crate::cancel::DrainPhase::SlowTail,
            converging: false,
            confidence_bound: 0.25,
            estimated_remaining_steps: Some(2.0),
            stall_detected: true,
            reached_quiescence: false,
            hard_deadline_hit: true,
            drain_duration: Duration::from_millis(77),
        });

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.accepted_total, 1);
        assert_eq!(snapshot.transient_accept_errors_total, 1);
        assert_eq!(snapshot.spawn_failures_total, 1);
        assert_eq!(snapshot.tls_handshake_rejections_total, 1);
        assert_eq!(snapshot.last_accept_at_ms, 321);
        assert_eq!(snapshot.drains_started_total, 1);
        assert_eq!(snapshot.drain_escalations_total, 1);
        assert_eq!(snapshot.drain_hard_deadline_hits_total, 1);
        assert_eq!(snapshot.drains_quiescent_total, 0);
        assert_eq!(snapshot.last_drain_requests_at_start, 3);
        assert_eq!(snapshot.last_drain_requests_stranded, 2);
        assert_eq!(snapshot.last_drain_duration_ms, 77);
    }

    #[test]
    fn stats_handle_uses_configured_time_getter() {
        crate::test_utils::run_test(|| async {
            let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
            let listener = Http2Listener::from_listener(
                tcp,
                |_req| async { Response::new(200, "OK", Vec::new()) },
                Http2ListenerConfig::default().time_getter(h2_listener_test_time),
            );

            set_h2_listener_test_time(Time::from_millis(456));
            listener.stats_handle().record_accepted();

            assert_eq!(listener.stats_handle().snapshot().last_accept_at_ms, 456);
        });
    }

    #[test]
    fn continuation_split_headers_map_to_listener_request() {
        let mut conn = Connection::server(Settings::default());
        assert!(
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                Vec::new()
            )))
            .expect("initial settings accepted")
            .is_none()
        );

        let encoded = encode_hpack_test_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/split-continuation"),
            (":authority", "split.example"),
            ("x-trace", "split-block"),
        ]);
        assert!(encoded.len() > 1, "test header block must be splittable");
        let split = encoded.len() / 2;

        assert!(
            conn.process_frame(Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
                1,
                encoded.slice(..split),
                true,
                false
            )))
            .expect("partial HEADERS accepted")
            .is_none()
        );

        let received = conn
            .process_frame(Frame::Continuation(
                crate::http::h2::frame::ContinuationFrame {
                    stream_id: 1,
                    header_block: encoded.slice(split..),
                    end_headers: true,
                },
            ))
            .expect("CONTINUATION completes header block")
            .expect("decoded header block emitted");

        let ReceivedFrame::Headers {
            stream_id,
            headers,
            end_stream,
        } = received
        else {
            panic!("expected decoded request headers");
        };

        assert_eq!(stream_id, 1);
        assert!(end_stream, "END_STREAM survives split header assembly");

        let peer = "127.0.0.1:8443".parse().expect("test peer parses");
        let request = request_from_h2_headers(headers, Vec::new(), Some(peer))
            .expect("listener accepts decoded split header block");

        assert_eq!(request.method, Method::Get);
        assert_eq!(request.uri, "/split-continuation");
        assert_eq!(request.version, Version::Http2);
        assert_eq!(request.peer_addr, Some(peer));
        assert_eq!(
            request.headers,
            vec![
                ("host".to_owned(), "split.example".to_owned()),
                ("x-trace".to_owned(), "split-block".to_owned()),
            ]
        );
    }

    #[test]
    fn response_guard_lives_until_queued_stream_frames_flush() {
        let mut conn = Connection::server(Settings::default());
        assert!(
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                Vec::new()
            )))
            .expect("initial settings accepted")
            .is_none()
        );

        let request_headers = encode_hpack_test_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/guard"),
            (":authority", "guard.example"),
        ]);
        let received = conn
            .process_frame(Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
                1,
                request_headers,
                true,
                true,
            )))
            .expect("request headers accepted");
        assert!(
            matches!(received, Some(ReceivedFrame::Headers { stream_id: 1, .. })),
            "request stream must be established before queuing a response"
        );

        let in_flight = Arc::new(AtomicUsize::new(0));
        let guard = InFlightRequestGuard::acquire(Some(&in_flight));
        assert_eq!(in_flight.load(Ordering::Acquire), 1);

        let mut response_guards = HashMap::new();
        queue_h2_response(
            &mut conn,
            1,
            Response::new(200, "OK", b"hello".to_vec()),
            guard,
            false,
            &mut response_guards,
        );

        assert_eq!(
            in_flight.load(Ordering::Acquire),
            1,
            "guard remains active while response frames are queued"
        );
        assert!(response_guards.contains_key(&1));
        assert!(conn.has_pending_frames_for_stream(1));

        release_flushed_response_guards(&conn, &mut response_guards);
        assert_eq!(
            in_flight.load(Ordering::Acquire),
            1,
            "pending stream frames keep the guard alive"
        );

        while conn.has_pending_frames_for_stream(1) {
            assert!(
                conn.next_frame().is_some(),
                "pending stream frames must eventually flush"
            );
        }
        release_flushed_response_guards(&conn, &mut response_guards);

        assert!(response_guards.is_empty());
        assert_eq!(
            in_flight.load(Ordering::Acquire),
            0,
            "guard releases only after the stream has no queued frames"
        );
    }

    #[test]
    fn queue_h2_response_synthesizes_500_for_invalid_response_headers() {
        let mut conn = Connection::server(Settings::default());
        assert!(
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                Vec::new()
            )))
            .expect("initial settings accepted")
            .is_none()
        );

        let request_headers = encode_hpack_test_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/invalid-response"),
            (":authority", "example.com"),
        ]);
        let received = conn
            .process_frame(Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
                1,
                request_headers,
                true,
                true,
            )))
            .expect("request headers accepted");
        assert!(matches!(received, Some(ReceivedFrame::Headers { .. })));

        let mut response_guards = HashMap::new();
        let outcomes = queue_h2_response(
            &mut conn,
            1,
            Response::new(200, "OK", b"secret".to_vec()).with_header("x-bad", "ok\r\nbad"),
            InFlightRequestGuard::acquire(None),
            false,
            &mut response_guards,
        );
        assert!(outcomes.is_empty());

        // Drain the SETTINGS ACK the connection queues in response to the peer
        // SETTINGS processed above before inspecting the response frames (same
        // ordering the push tests account for).
        match conn.next_frame().expect("settings ack") {
            Frame::Settings(settings) => assert!(settings.ack, "expected SETTINGS ACK first"),
            other => panic!("expected SETTINGS ACK, got {other:?}"),
        }

        let frame = conn.next_frame().expect("fallback response headers");
        let Frame::Headers(headers) = frame else {
            panic!("expected fallback response HEADERS, got {frame:?}");
        };
        assert!(headers.end_stream, "fallback response has no body");
        let mut block = headers.header_block;
        let decoded = crate::http::h2::HpackDecoder::new()
            .decode(&mut block)
            .expect("fallback headers decode");
        assert!(decoded.contains(&Header::new(":status", "500")));
        assert!(
            decoded.iter().all(|header| header.name != "x-bad"),
            "invalid handler header must not reach HPACK output: {decoded:?}"
        );
        assert!(conn.next_frame().is_none());
        // queue_h2_response retains the in-flight guard until the stream's frames
        // flush (retain-until-flush model); release it now that the stream has no
        // pending frames, mirroring the serve loop, then confirm no guard leaked.
        release_flushed_response_guards(&conn, &mut response_guards);
        assert!(response_guards.is_empty());
    }

    #[test]
    fn queue_h2_response_emits_trailing_headers_after_body() {
        let mut conn = Connection::server(Settings::default());
        assert!(
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                Vec::new()
            )))
            .expect("initial settings accepted")
            .is_none()
        );

        let request_headers = encode_hpack_test_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/trailers"),
            (":authority", "example.com"),
        ]);
        let received = conn
            .process_frame(Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
                1,
                request_headers,
                true,
                true,
            )))
            .expect("request headers accepted");
        assert!(matches!(received, Some(ReceivedFrame::Headers { .. })));

        let mut response_guards = HashMap::new();
        let outcomes = queue_h2_response(
            &mut conn,
            1,
            Response::new(200, "OK", b"hello".to_vec()).with_trailer("X-Trace", "abc123"),
            InFlightRequestGuard::acquire(None),
            false,
            &mut response_guards,
        );
        assert!(outcomes.is_empty());

        // Drain the SETTINGS ACK queued for the peer SETTINGS before inspecting
        // the response frames.
        match conn.next_frame().expect("settings ack") {
            Frame::Settings(settings) => assert!(settings.ack, "expected SETTINGS ACK first"),
            other => panic!("expected SETTINGS ACK, got {other:?}"),
        }

        let mut decoder = crate::http::h2::HpackDecoder::new();
        match conn.next_frame().expect("response headers") {
            Frame::Headers(headers) => {
                assert_eq!(headers.stream_id, 1);
                assert!(!headers.end_stream);
                let mut block = headers.header_block;
                let decoded = decoder.decode(&mut block).expect("response headers decode");
                assert!(decoded.contains(&Header::new(":status", "200")));
            }
            other => panic!("expected response HEADERS, got {other:?}"),
        }
        match conn.next_frame().expect("response body") {
            Frame::Data(data) => {
                assert_eq!(data.stream_id, 1);
                assert_eq!(data.data, crate::bytes::Bytes::from_static(b"hello"));
                assert!(
                    !data.end_stream,
                    "DATA must leave the stream open for trailers"
                );
            }
            other => panic!("expected response DATA, got {other:?}"),
        }
        match conn.next_frame().expect("response trailers") {
            Frame::Headers(headers) => {
                assert_eq!(headers.stream_id, 1);
                assert!(headers.end_stream);
                let mut block = headers.header_block;
                let decoded = decoder
                    .decode(&mut block)
                    .expect("response trailers decode");
                assert_eq!(decoded, vec![Header::new("x-trace", "abc123")]);
            }
            other => panic!("expected response trailer HEADERS, got {other:?}"),
        }
        assert!(conn.next_frame().is_none());
    }

    #[test]
    fn handler_panic_maps_to_500_and_releases_guard_after_flush() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime.block_on(async move {
            let cx = Cx::current().expect("runtime installs Cx for block_on");
            let mut conn = Connection::server(Settings::default());
            assert!(
                conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                    Vec::new()
                )))
                .expect("initial settings accepted")
                .is_none()
            );

            let request_headers = encode_hpack_test_headers(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/panic"),
                (":authority", "panic.example"),
            ]);
            let received = conn
                .process_frame(Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
                    1,
                    request_headers,
                    true,
                    true,
                )))
                .expect("request headers accepted")
                .expect("request headers decoded");
            let ReceivedFrame::Headers {
                stream_id,
                headers,
                end_stream,
            } = received
            else {
                panic!("expected decoded request headers");
            };
            assert_eq!(stream_id, 1);
            assert!(end_stream);

            let (resp_tx, mut resp_rx) = mpsc::channel::<FunnelItem>(RESPONSE_FUNNEL_CAPACITY);
            let shutdown_signal = ShutdownSignal::new();
            let in_flight = Arc::new(AtomicUsize::new(0));
            let handler = Arc::new(panicking_h2_handler);

            let _coordinator = dispatch_h2_request(
                &mut conn,
                stream_id,
                headers,
                Vec::new(),
                Vec::new(),
                None,
                &handler,
                &resp_tx,
                &shutdown_signal,
                &in_flight,
                &cx,
                &HostPolicy::allow_list(vec!["panic.example".to_owned()]),
                None,
                None,
                Duration::from_millis(500),
                None,
                true,
                usize::MAX,
            ).expect("dispatch coordinator");

            let item = resp_rx
                .recv(&cx)
                .await
                .expect("panic response must be sent through funnel");
            let FunnelItem::Response {
                stream_id: response_stream,
                response,
                guard,
                suppress_response_body,
            } = item
            else {
                panic!("expected handler response, got stream timeout");
            };
            assert_eq!(response_stream, 1);
            assert_eq!(response.response.status, 500);
            assert_eq!(response.response.reason, "Internal Server Error");
            assert!(response.response.body.is_empty());
            assert!(!suppress_response_body);
            assert_eq!(
                in_flight.load(Ordering::Acquire),
                1,
                "guard remains active until the 500 response is queued and flushed"
            );

            let mut response_guards = HashMap::new();
            queue_h2_response(
                &mut conn,
                response_stream,
                response,
                guard,
                suppress_response_body,
                &mut response_guards,
            );
            while conn.has_pending_frames_for_stream(response_stream) {
                assert!(
                    conn.next_frame().is_some(),
                    "500 response frames must be flushable"
                );
            }
            release_flushed_response_guards(&conn, &mut response_guards);

            assert!(response_guards.is_empty());
            assert_eq!(
                in_flight.load(Ordering::Acquire),
                0,
                "handler-panic guard releases after the synthesized response flushes"
            );
        });
    }

    #[test]
    fn disallowed_host_returns_421_without_invoking_handler() {
        // br-asupersync-mfqfst M8: a request whose :authority/host is not on
        // the allow-list gets a per-stream 421 Misdirected Request and the
        // handler never runs.
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime.block_on(async move {
            let cx = Cx::current().expect("runtime installs Cx for block_on");
            let mut conn = Connection::server(Settings::default());

            let (resp_tx, mut resp_rx) = mpsc::channel::<FunnelItem>(RESPONSE_FUNNEL_CAPACITY);
            let shutdown_signal = ShutdownSignal::new();
            let in_flight = Arc::new(AtomicUsize::new(0));
            let invoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let invoked_for_handler = Arc::clone(&invoked);
            let handler = Arc::new(move |_req: Request| {
                let invoked = Arc::clone(&invoked_for_handler);
                async move {
                    invoked.store(true, Ordering::SeqCst);
                    H2DispatchResponse::Buffered(
                        Response::new(200, "OK", Vec::new()).into_h2_response(),
                    )
                }
            });

            // request_block carries `:authority example.com:8443` -> host
            // `example.com`, which is NOT on this allow-list.
            let _coordinator = dispatch_h2_request(
                &mut conn,
                1,
                request_block(&[]),
                Vec::new(),
                Vec::new(),
                None,
                &handler,
                &resp_tx,
                &shutdown_signal,
                &in_flight,
                &cx,
                &HostPolicy::allow_list(vec!["allowed.example".to_owned()]),
                None,
                None,
                Duration::from_millis(500),
                None,
                true,
                usize::MAX,
            ).expect("dispatch coordinator");

            let item = resp_rx
                .recv(&cx)
                .await
                .expect("421 response must be sent through funnel");
            let FunnelItem::Response {
                stream_id,
                response,
                guard,
                suppress_response_body: _,
            } = item
            else {
                panic!("expected host-rejection response, got stream timeout");
            };
            assert_eq!(stream_id, 1);
            assert_eq!(response.response.status, 421);
            assert!(
                String::from_utf8_lossy(&response.response.body).contains("example.com"),
                "421 body should name the rejected host: {:?}",
                response.response.body
            );
            assert!(
                !invoked.load(Ordering::SeqCst),
                "handler must not run for a rejected host"
            );
            drop(guard);
        });
    }

    #[test]
    fn allowed_host_runs_handler() {
        // br-asupersync-mfqfst M8: a request whose host is on the allow-list
        // reaches the handler and its response is funneled back.
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime.block_on(async move {
            let cx = Cx::current().expect("runtime installs Cx for block_on");
            let mut conn = Connection::server(Settings::default());

            let (resp_tx, mut resp_rx) = mpsc::channel::<FunnelItem>(RESPONSE_FUNNEL_CAPACITY);
            let shutdown_signal = ShutdownSignal::new();
            let in_flight = Arc::new(AtomicUsize::new(0));
            let invoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let invoked_for_handler = Arc::clone(&invoked);
            let handler = Arc::new(move |_req: Request| {
                let invoked = Arc::clone(&invoked_for_handler);
                async move {
                    invoked.store(true, Ordering::SeqCst);
                    H2DispatchResponse::Buffered(
                        Response::new(200, "OK", b"hi".to_vec()).into_h2_response(),
                    )
                }
            });

            let _coordinator = dispatch_h2_request(
                &mut conn,
                1,
                request_block(&[]),
                Vec::new(),
                Vec::new(),
                None,
                &handler,
                &resp_tx,
                &shutdown_signal,
                &in_flight,
                &cx,
                &HostPolicy::allow_list(vec!["example.com".to_owned()]),
                None,
                None,
                Duration::from_millis(500),
                None,
                true,
                usize::MAX,
            ).expect("dispatch coordinator");

            let item = resp_rx
                .recv(&cx)
                .await
                .expect("handler response must be sent through funnel");
            let FunnelItem::Response {
                stream_id,
                response,
                guard,
                suppress_response_body: _,
            } = item
            else {
                panic!("expected handler response, got stream timeout");
            };
            assert_eq!(stream_id, 1);
            assert_eq!(response.response.status, 200);
            assert!(
                invoked.load(Ordering::SeqCst),
                "handler must run for an allow-listed host"
            );
            drop(guard);
        });
    }

    #[test]
    fn stream_idle_timeout_drops_handler_and_returns_reset_outcome() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");

        runtime.block_on(async move {
            let cx = Cx::current().expect("runtime installs Cx for block_on");
            let mut conn = Connection::server(Settings::default());
            let (resp_tx, mut resp_rx) = mpsc::channel::<FunnelItem>(RESPONSE_FUNNEL_CAPACITY);
            let shutdown_signal = ShutdownSignal::new();
            let in_flight = Arc::new(AtomicUsize::new(0));
            let handler = Arc::new(|_req: Request| std::future::pending::<H2DispatchResponse>());

            let _coordinator = dispatch_h2_request(
                &mut conn,
                1,
                request_block(&[]),
                Vec::new(),
                Vec::new(),
                None,
                &handler,
                &resp_tx,
                &shutdown_signal,
                &in_flight,
                &cx,
                &HostPolicy::allow_list(vec!["example.com".to_owned()]),
                None,
                None,
                Duration::from_millis(500),
                Some(Duration::ZERO),
                true,
                usize::MAX,
            ).expect("dispatch coordinator");

            let item = resp_rx
                .recv(&cx)
                .await
                .expect("idle timeout must be sent through funnel");
            let FunnelItem::StreamIdleTimeout { stream_id, guard } = item else {
                panic!("pending handler must produce stream timeout, not a response");
            };
            assert_eq!(stream_id, 1);
            assert_eq!(in_flight.load(Ordering::Acquire), 1);
            drop(guard);
            assert_eq!(in_flight.load(Ordering::Acquire), 0);
        });
    }

    #[test]
    fn frame_codec_for_honors_local_max_frame_size() {
        use crate::bytes::BytesMut;
        use crate::codec::Decoder;
        use crate::http::h2::frame::DEFAULT_MAX_FRAME_SIZE;

        // A conformant DATA frame on stream 1 whose payload (20000 bytes)
        // exceeds the 16384 protocol default but fits inside a larger advertised
        // SETTINGS_MAX_FRAME_SIZE. 9-byte header: length=20000 (0x004E20),
        // type=DATA(0x0), flags=0, stream id=1.
        let mut frame_bytes = vec![0x00, 0x4E, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        frame_bytes.resize(9 + 20_000, 0u8);

        // The protocol-default accept limit (the pre-fix listener behavior)
        // rejects the frame with FRAME_SIZE_ERROR.
        let mut default_codec = frame_codec_for(DEFAULT_MAX_FRAME_SIZE);
        let mut src = BytesMut::new();
        src.extend_from_slice(&frame_bytes);
        let err = default_codec
            .decode(&mut src)
            .expect_err("default 16 KiB accept limit must reject a 20000-byte frame");
        assert_eq!(err.code, ErrorCode::FrameSizeError);

        // A listener advertising max_frame_size=32768 accepts the same frame.
        let mut wide_codec = frame_codec_for(32_768);
        let mut src = BytesMut::new();
        src.extend_from_slice(&frame_bytes);
        let frame = wide_codec
            .decode(&mut src)
            .expect("decode succeeds under the advertised limit")
            .expect("a full frame is available");
        assert!(
            matches!(frame, DecodedFrame::Frame(Frame::Data(_))),
            "expected a DATA frame, got {frame:?}",
        );
    }

    #[test]
    fn listener_framed_reads_a_frame_over_eight_mib_that_the_settings_allow() {
        use crate::stream::Stream as _;
        use std::task::Waker;

        // A DATA frame of 0x900000 bytes (9 MiB) on stream 1, then a PING.
        // SETTINGS_MAX_FRAME_SIZE may advertise up to 16 MiB - 1.
        let len = 9 * 1024 * 1024;
        let mut wire = vec![0x90, 0x00, 0x00, 0x0, 0x0, 0, 0, 0, 1];
        wire.resize(9 + len, 0);
        wire.extend_from_slice(&[0, 0, 8, 0x6, 0, 0, 0, 0, 0, 7, 7, 7, 7, 7, 7, 7, 7]);
        let mut framed = listener_framed(std::io::Cursor::new(wire), (1 << 24) - 1);
        let mut context = Context::from_waker(Waker::noop());
        let mut next = || {
            for _ in 0..10_000 {
                if let Poll::Ready(item) = Pin::new(&mut framed).poll_next(&mut context) {
                    return item;
                }
            }
            panic!("the framed reader never produced a frame");
        };
        match next() {
            Some(Ok(DecodedFrame::Frame(Frame::Data(data)))) => assert_eq!(data.data.len(), len),
            other => panic!("expected the 9 MiB DATA frame, got {other:?}"),
        }
        let ping = next();
        assert!(
            matches!(ping, Some(Ok(DecodedFrame::Frame(Frame::Ping(_))))),
            "expected the PING after it, got {ping:?}",
        );
    }

    #[test]
    fn request_mapping_extracts_pseudo_headers_and_synthesizes_host() {
        let request =
            request_from_h2_headers(request_block(&[("x-trace", "abc")]), b"body".to_vec(), None)
                .expect("valid request block");
        assert_eq!(request.method, Method::Get);
        assert_eq!(request.uri, "/widgets?q=1");
        assert_eq!(request.version, Version::Http2);
        assert_eq!(request.body, b"body");
        assert_eq!(
            request.headers,
            vec![
                ("host".to_owned(), "example.com:8443".to_owned()),
                ("x-trace".to_owned(), "abc".to_owned()),
            ]
        );
    }

    #[test]
    fn request_mapping_preserves_trailer_block_separately() {
        let request = request_from_h2_parts(
            request_block(&[("x-trace", "abc")]),
            b"body".to_vec(),
            vec![
                Header::new("x-client-tail", "tail-value"),
                Header::new("x-client-token-bin", "AQI"),
            ],
            None,
        )
        .expect("valid request and trailer blocks");

        assert_eq!(
            request.trailers,
            vec![
                ("x-client-tail".to_owned(), "tail-value".to_owned()),
                ("x-client-token-bin".to_owned(), "AQI".to_owned()),
            ]
        );
        assert!(
            request
                .headers
                .iter()
                .all(|(name, _)| !name.eq_ignore_ascii_case("x-client-tail"))
        );
    }

    #[test]
    fn request_mapping_rejects_trailer_pseudo_header() {
        let result = request_from_h2_parts(
            request_block(&[]),
            Vec::new(),
            vec![Header::new(":status", "200")],
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn request_mapping_keeps_explicit_host_over_authority() {
        let request = request_from_h2_headers(
            request_block(&[("host", "explicit.example")]),
            Vec::new(),
            None,
        )
        .expect("valid request block");
        let hosts: Vec<_> = request
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
            .collect();
        assert_eq!(hosts.len(), 1, "no duplicate host header");
        assert_eq!(hosts[0].1, "explicit.example");
    }

    #[test]
    fn request_mapping_rejects_missing_method_and_path() {
        let no_method = vec![Header::new(":path", "/"), Header::new(":scheme", "https")];
        assert!(request_from_h2_headers(no_method, Vec::new(), None).is_err());

        let no_path = vec![
            Header::new(":method", "GET"),
            Header::new(":scheme", "https"),
        ];
        assert!(request_from_h2_headers(no_path, Vec::new(), None).is_err());
    }

    #[test]
    fn request_mapping_rejects_unknown_pseudo_header() {
        let block = request_block(&[(":bogus", "x")]);
        assert!(request_from_h2_headers(block, Vec::new(), None).is_err());
    }

    #[test]
    fn response_mapping_emits_status_first_and_strips_h1_connection_headers() {
        let response = Response {
            version: Version::Http2,
            status: 204,
            reason: "No Content".to_owned(),
            headers: vec![
                ("Connection".to_owned(), "close".to_owned()),
                ("Transfer-Encoding".to_owned(), "chunked".to_owned()),
                ("TE".to_owned(), "gzip".to_owned()),
                ("X-Trace".to_owned(), "abc".to_owned()),
            ],
            body: Vec::new(),
            trailers: Vec::new(),
        };
        let block = h2_headers_from_response(&response).expect("valid response headers");
        assert_eq!(block[0], Header::new(":status", "204"));
        assert_eq!(block.len(), 2, "connection-specific headers stripped");
        assert_eq!(block[1], Header::new("x-trace", "abc"));
    }

    #[test]
    fn response_mapping_keeps_te_trailers() {
        let response = Response {
            version: Version::Http2,
            status: 200,
            reason: "OK".to_owned(),
            headers: vec![("te".to_owned(), "trailers".to_owned())],
            body: Vec::new(),
            trailers: Vec::new(),
        };
        let block = h2_headers_from_response(&response).expect("valid TE trailers header");
        assert_eq!(block.len(), 2);
        assert_eq!(block[1], Header::new("te", "trailers"));
    }

    #[test]
    fn response_mapping_rejects_invalid_handler_supplied_headers() {
        let crlf = Response::new(200, "OK", Vec::new()).with_header("x-trace", "ok\r\nbad");
        assert!(h2_headers_from_response(&crlf).is_err());

        let nul = Response::new(200, "OK", Vec::new()).with_header("x-trace", "bad\0value");
        assert!(h2_headers_from_response(&nul).is_err());

        let bad_name = Response::new(200, "OK", Vec::new()).with_header("x bad", "value");
        assert!(h2_headers_from_response(&bad_name).is_err());

        let pseudo = Response::new(200, "OK", Vec::new()).with_header(":path", "/forged");
        assert!(h2_headers_from_response(&pseudo).is_err());

        let bad_trailer =
            Response::new(200, "OK", Vec::new()).with_trailer("x-trace", "bad\nvalue");
        assert!(validate_h2_response_for_queue(&bad_trailer, false).is_err());
    }

    #[test]
    fn response_content_length_validation_respects_head_suppression() {
        let mismatch = Response::new(200, "OK", b"abc".to_vec()).with_header("Content-Length", "4");
        assert!(validate_h2_response_for_queue(&mismatch, true).is_err());
        assert!(validate_h2_response_for_queue(&mismatch, false).is_ok());

        let invalid = Response::new(200, "OK", b"abc".to_vec()).with_header("Content-Length", "+3");
        assert!(validate_h2_response_for_queue(&invalid, false).is_err());

        let duplicate = Response {
            version: Version::Http2,
            status: 200,
            reason: "OK".to_owned(),
            headers: vec![
                ("Content-Length".to_owned(), "3".to_owned()),
                ("content-length".to_owned(), "3".to_owned()),
            ],
            body: b"abc".to_vec(),
            trailers: Vec::new(),
        };
        assert!(validate_h2_response_for_queue(&duplicate, true).is_err());
    }

    #[test]
    fn plain_response_converts_to_h2_response_without_pushes() {
        let response = Response::new(200, "OK", b"plain".to_vec());
        let h2_response = response.into_h2_response();

        assert_eq!(h2_response.response.status, 200);
        assert!(h2_response.pushes.is_empty());
    }

    #[test]
    fn queue_h2_response_promises_pushed_resource_before_parent_response() {
        let mut conn = Connection::server(Settings::default());
        assert!(
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                Vec::new()
            )))
            .expect("initial settings accepted")
            .is_none()
        );
        expect_settings_ack(&mut conn);

        let request_headers = encode_hpack_test_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/index.html"),
            (":authority", "push.example"),
        ]);
        let received = conn
            .process_frame(Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
                1,
                request_headers,
                true,
                true,
            )))
            .expect("request headers accepted");
        assert!(matches!(
            received,
            Some(ReceivedFrame::Headers { stream_id: 1, .. })
        ));

        let pushed = Http2ServerPush::get(
            "/style.css",
            "push.example",
            Response::new(200, "OK", b"css".to_vec()).with_header("Content-Type", "text/css"),
        );
        let response =
            Http2Response::new(Response::new(200, "OK", b"html".to_vec())).with_push(pushed);
        let mut response_guards = HashMap::new();
        let outcomes = queue_h2_response(
            &mut conn,
            1,
            response,
            InFlightRequestGuard::acquire(None),
            false,
            &mut response_guards,
        );

        assert_eq!(
            outcomes,
            vec![Http2PushOutcome::Promised {
                associated_stream_id: 1,
                promised_stream_id: 2
            }]
        );

        match conn.next_frame().expect("PUSH_PROMISE should lead") {
            Frame::PushPromise(push) => {
                assert_eq!(push.stream_id, 1);
                assert_eq!(push.promised_stream_id, 2);
                assert!(push.end_headers);
            }
            other => panic!("expected PUSH_PROMISE, got {other:?}"),
        }
        match conn.next_frame().expect("promised response headers") {
            Frame::Headers(headers) => {
                assert_eq!(headers.stream_id, 2);
                assert!(!headers.end_stream);
            }
            other => panic!("expected promised response HEADERS, got {other:?}"),
        }
        match conn.next_frame().expect("promised response body") {
            Frame::Data(data) => {
                assert_eq!(data.stream_id, 2);
                assert_eq!(data.data, crate::bytes::Bytes::from_static(b"css"));
                assert!(data.end_stream);
            }
            other => panic!("expected promised response DATA, got {other:?}"),
        }
        match conn.next_frame().expect("parent response headers") {
            Frame::Headers(headers) => {
                assert_eq!(headers.stream_id, 1);
                assert!(!headers.end_stream);
            }
            other => panic!("expected parent response HEADERS, got {other:?}"),
        }
        match conn.next_frame().expect("parent response body") {
            Frame::Data(data) => {
                assert_eq!(data.stream_id, 1);
                assert_eq!(data.data, crate::bytes::Bytes::from_static(b"html"));
                assert!(data.end_stream);
            }
            other => panic!("expected parent response DATA, got {other:?}"),
        }
    }

    #[test]
    fn queue_h2_response_reports_peer_disabled_no_push() {
        let mut conn = Connection::server(Settings::default());
        assert!(
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                vec![crate::http::h2::frame::Setting::EnablePush(false)]
            )))
            .expect("initial settings accepted")
            .is_none()
        );
        expect_settings_ack(&mut conn);

        let request_headers = encode_hpack_test_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/index.html"),
            (":authority", "push.example"),
        ]);
        let received = conn
            .process_frame(Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
                1,
                request_headers,
                true,
                true,
            )))
            .expect("request headers accepted");
        assert!(matches!(
            received,
            Some(ReceivedFrame::Headers { stream_id: 1, .. })
        ));

        let response = Http2Response::new(Response::new(200, "OK", Vec::new())).with_push(
            Http2ServerPush::get(
                "/style.css",
                "push.example",
                Response::new(200, "OK", Vec::new()),
            ),
        );
        let mut response_guards = HashMap::new();
        let outcomes = queue_h2_response(
            &mut conn,
            1,
            response,
            InFlightRequestGuard::acquire(None),
            false,
            &mut response_guards,
        );

        assert_eq!(
            outcomes,
            vec![Http2PushOutcome::NotPushed {
                associated_stream_id: 1,
                reason: Http2PushRejection::PeerDisabled
            }]
        );
        assert!(conn.stream(2).is_none());
        match conn.next_frame().expect("parent response still queues") {
            Frame::Headers(headers) => {
                assert_eq!(headers.stream_id, 1);
                assert!(headers.end_stream);
            }
            other => panic!("expected parent response HEADERS, got {other:?}"),
        }
        assert!(conn.next_frame().is_none());
    }

    #[test]
    fn queue_h2_response_reports_goaway_push_rejection() {
        let mut conn = Connection::server(Settings::default());
        assert!(
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                Vec::new()
            )))
            .expect("initial settings accepted")
            .is_none()
        );
        expect_settings_ack(&mut conn);

        let request_headers = encode_hpack_test_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/index.html"),
            (":authority", "push.example"),
        ]);
        let received = conn
            .process_frame(Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
                1,
                request_headers,
                true,
                true,
            )))
            .expect("request headers accepted");
        assert!(matches!(
            received,
            Some(ReceivedFrame::Headers { stream_id: 1, .. })
        ));

        conn.goaway(
            ErrorCode::NoError,
            crate::bytes::Bytes::from_static(b"server draining"),
        );
        let response = Http2Response::new(Response::new(200, "OK", Vec::new())).with_push(
            Http2ServerPush::get(
                "/style.css",
                "push.example",
                Response::new(200, "OK", Vec::new()),
            ),
        );
        let mut response_guards = HashMap::new();
        let outcomes = queue_h2_response(
            &mut conn,
            1,
            response,
            InFlightRequestGuard::acquire(None),
            false,
            &mut response_guards,
        );

        assert_eq!(
            outcomes,
            vec![Http2PushOutcome::NotPushed {
                associated_stream_id: 1,
                reason: Http2PushRejection::ConnectionClosing
            }]
        );
        assert!(conn.stream(2).is_none());
        assert!(matches!(conn.next_frame(), Some(Frame::GoAway(_))));
        match conn.next_frame().expect("parent response still queues") {
            Frame::Headers(headers) => {
                assert_eq!(headers.stream_id, 1);
                assert!(headers.end_stream);
            }
            other => panic!("expected parent response HEADERS, got {other:?}"),
        }
    }

    #[test]
    fn queue_h2_response_reports_max_concurrent_push_rejection() {
        let mut conn = Connection::server(Settings::default());
        assert!(
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                vec![crate::http::h2::frame::Setting::MaxConcurrentStreams(1)]
            )))
            .expect("max concurrent settings accepted")
            .is_none()
        );
        expect_settings_ack(&mut conn);

        let request_headers = encode_hpack_test_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/index.html"),
            (":authority", "push.example"),
        ]);
        let received = conn
            .process_frame(Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
                1,
                request_headers,
                true,
                true,
            )))
            .expect("request headers accepted");
        assert!(matches!(
            received,
            Some(ReceivedFrame::Headers { stream_id: 1, .. })
        ));

        // The peer's limit applies to streams we initiate, not its request.
        // Occupy its one slot with an actual active pushed response first.
        let occupied = conn
            .send_push_promise(
                1,
                vec![
                    Header::new(":method", "GET"),
                    Header::new(":scheme", "https"),
                    Header::new(":path", "/held.css"),
                    Header::new(":authority", "push.example"),
                ],
            )
            .expect("the first push is independent of the incoming request limit");
        assert_eq!(occupied, 2);
        conn.send_headers(occupied, vec![Header::new(":status", "200")], false)
            .unwrap();
        assert!(
            matches!(conn.next_frame(), Some(Frame::PushPromise(frame)) if frame.promised_stream_id == occupied)
        );
        assert!(
            matches!(conn.next_frame(), Some(Frame::Headers(frame)) if frame.stream_id == occupied && !frame.end_stream)
        );

        let response = Http2Response::new(Response::new(200, "OK", Vec::new())).with_push(
            Http2ServerPush::get(
                "/style.css",
                "push.example",
                Response::new(200, "OK", Vec::new()),
            ),
        );
        let mut response_guards = HashMap::new();
        let outcomes = queue_h2_response(
            &mut conn,
            1,
            response,
            InFlightRequestGuard::acquire(None),
            false,
            &mut response_guards,
        );

        assert_eq!(outcomes.len(), 1);
        match &outcomes[0] {
            Http2PushOutcome::NotPushed {
                associated_stream_id,
                reason:
                    Http2PushRejection::Rejected {
                        code,
                        stream_id,
                        message,
                    },
            } => {
                assert_eq!(*associated_stream_id, 1);
                assert_eq!(*code, ErrorCode::ProtocolError);
                assert_eq!(*stream_id, None);
                assert!(message.contains("max concurrent streams exceeded"));
            }
            other => panic!("expected typed max-concurrent push rejection, got {other:?}"),
        }
        assert!(
            conn.stream(occupied).is_some(),
            "existing push must survive rejection"
        );
        assert!(
            conn.stream(4).is_none(),
            "rejected push cannot reserve a stream"
        );
        match conn.next_frame().expect("parent response still queues") {
            Frame::Headers(headers) => {
                assert_eq!(headers.stream_id, 1);
                assert!(headers.end_stream);
            }
            other => panic!("expected parent response HEADERS, got {other:?}"),
        }
        conn.reset_stream(occupied, ErrorCode::Cancel);
        assert!(
            matches!(conn.next_frame(), Some(Frame::RstStream(frame)) if frame.stream_id == occupied)
        );
        assert_eq!(conn.active_stream_count(), 0);
    }

    #[test]
    fn queue_h2_response_reports_parent_cancelled_without_promising() {
        let mut conn = Connection::server(Settings::default());
        assert!(
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                Vec::new()
            )))
            .expect("initial settings accepted")
            .is_none()
        );
        expect_settings_ack(&mut conn);

        let request_headers = encode_hpack_test_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/index.html"),
            (":authority", "push.example"),
        ]);
        let received = conn
            .process_frame(Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
                1,
                request_headers,
                true,
                true,
            )))
            .expect("request headers accepted");
        assert!(matches!(
            received,
            Some(ReceivedFrame::Headers { stream_id: 1, .. })
        ));
        let reset = conn
            .process_frame(Frame::RstStream(
                crate::http::h2::frame::RstStreamFrame::new(1, ErrorCode::Cancel),
            ))
            .expect("parent reset accepted");
        assert!(matches!(
            reset,
            Some(ReceivedFrame::Reset {
                stream_id: 1,
                error_code: ErrorCode::Cancel
            })
        ));

        let response = Http2Response::new(Response::new(200, "OK", b"html".to_vec())).with_push(
            Http2ServerPush::get(
                "/style.css",
                "push.example",
                Response::new(200, "OK", b"css".to_vec()),
            ),
        );
        let mut response_guards = HashMap::new();
        let outcomes = queue_h2_response(
            &mut conn,
            1,
            response,
            InFlightRequestGuard::acquire(None),
            false,
            &mut response_guards,
        );

        assert_eq!(
            outcomes,
            vec![Http2PushOutcome::NotPushed {
                associated_stream_id: 1,
                reason: Http2PushRejection::ParentCancelled
            }]
        );
        assert!(conn.stream(2).is_none());
        assert!(conn.next_frame().is_none());
    }

    #[test]
    fn parent_reset_cancels_queued_promised_stream_frames() {
        let mut conn = Connection::server(Settings::default());
        assert!(
            conn.process_frame(Frame::Settings(crate::http::h2::frame::SettingsFrame::new(
                Vec::new()
            )))
            .expect("initial settings accepted")
            .is_none()
        );
        expect_settings_ack(&mut conn);

        let request_headers = encode_hpack_test_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/index.html"),
            (":authority", "push.example"),
        ]);
        let received = conn
            .process_frame(Frame::Headers(crate::http::h2::frame::HeadersFrame::new(
                1,
                request_headers,
                true,
                true,
            )))
            .expect("request headers accepted");
        assert!(matches!(
            received,
            Some(ReceivedFrame::Headers { stream_id: 1, .. })
        ));

        let response = Http2Response::new(Response::new(200, "OK", b"html".to_vec())).with_push(
            Http2ServerPush::get(
                "/style.css",
                "push.example",
                Response::new(200, "OK", b"css".to_vec()),
            ),
        );
        let mut response_guards = HashMap::new();
        let outcomes = queue_h2_response(
            &mut conn,
            1,
            response,
            InFlightRequestGuard::acquire(None),
            false,
            &mut response_guards,
        );
        assert_eq!(
            outcomes,
            vec![Http2PushOutcome::Promised {
                associated_stream_id: 1,
                promised_stream_id: 2
            }]
        );

        let mut associated_pushes = HashMap::new();
        record_promised_pushes(&mut associated_pushes, &outcomes);
        assert!(conn.has_pending_frames_for_stream(2));

        let reset = conn
            .process_frame(Frame::RstStream(
                crate::http::h2::frame::RstStreamFrame::new(1, ErrorCode::Cancel),
            ))
            .expect("parent reset accepted");
        assert!(matches!(
            reset,
            Some(ReceivedFrame::Reset {
                stream_id: 1,
                error_code: ErrorCode::Cancel
            })
        ));
        reset_associated_pushes(&mut conn, &mut associated_pushes, 1);

        match conn
            .next_frame()
            .expect("promised stream reset should flush")
        {
            Frame::RstStream(reset) => {
                assert_eq!(reset.stream_id, 2);
                assert_eq!(reset.error_code, ErrorCode::Cancel);
            }
            other => panic!("expected promised-stream RST_STREAM, got {other:?}"),
        }
        assert!(conn.next_frame().is_none());
    }

    #[test]
    fn head_response_suppression_drops_body_and_synthesizes_length() {
        let mut response = Response::new(200, "OK", b"hello".to_vec())
            .with_header("Trailer", "X-Trace")
            .with_header("Transfer-Encoding", "chunked")
            .with_trailer("X-Trace", "abc123");

        suppress_response_body_for_head(&mut response);

        assert!(response.body.is_empty());
        assert!(response.trailers.is_empty());
        assert_eq!(response.header_value("content-length"), Some("5"));
        assert_eq!(response.header_value("trailer"), None);
        assert_eq!(response.header_value("transfer-encoding"), None);

        let block = h2_headers_from_response(&response).expect("valid HEAD response headers");
        assert!(
            block
                .iter()
                .any(|header| header.name == "content-length" && header.value == "5")
        );
        assert!(
            !block
                .iter()
                .any(|header| header.name == "trailer" || header.name == "transfer-encoding")
        );
    }

    #[test]
    fn head_response_suppression_preserves_explicit_length() {
        let mut response =
            Response::new(200, "OK", b"sentinel".to_vec()).with_header("Content-Length", "999");

        suppress_response_body_for_head(&mut response);

        assert!(response.body.is_empty());
        assert_eq!(response.header_value("content-length"), Some("999"));
    }

    /// The drain supervision tick waits its interval when the listener task
    /// is cancelled; it used to complete at once, so the drain loop spun.
    #[test]
    fn drain_supervision_tick_ignores_the_listener_tasks_cancellation() {
        let virtual_clock =
            std::sync::Arc::new(crate::time::VirtualClock::starting_at(Time::from_secs(10)));
        let timer_driver = crate::time::TimerDriverHandle::with_virtual_clock(
            std::sync::Arc::clone(&virtual_clock),
        );
        let cx = Cx::new_with_drivers(
            crate::types::RegionId::new_for_test(7, 2),
            crate::types::TaskId::new_for_test(9, 2),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(timer_driver.clone()),
            None,
        );
        cx.set_cancel_requested(true);
        let _guard = Cx::set_current(Some(cx));
        let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
        let mut tick = std::pin::pin!(drain_supervision_tick(Time::from_secs(10)));
        for _ in 0..2 {
            assert!(
                tick.as_mut().poll(&mut task_cx).is_pending(),
                "a cancelled listener still waits for the tick"
            );
        }
        virtual_clock.advance_to(Time::from_secs(10) + DRAIN_SUPERVISION_TICK);
        let _ = timer_driver.process_timers();
        assert!(tick.as_mut().poll(&mut task_cx).is_ready());
    }

    /// Exercise the listener failure boundary with a real HTTP/2 request,
    /// including its request region and the two-stage GOAWAY drain.
    #[cfg(not(target_arch = "wasm32"))]
    #[allow(clippy::too_many_lines)]
    fn fatal_listener_failure_drains_request(fail_spawn: bool, owned: bool, workers: usize) {
        use crate::bytes::BytesMut;
        use crate::codec::Decoder as _;
        use crate::http::h2::connection::FrameCodec;
        use crate::http::h2::frame::{HeadersFrame, SettingsFrame};
        use crate::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use crate::runtime::{RuntimeBuilder, yield_now};
        use crate::sync::Notify;
        use std::sync::atomic::AtomicBool;

        const WATCHDOG: Duration = Duration::from_secs(10);

        struct Cleanup {
            release: Arc<Notify>,
            signal: ShutdownSignal,
        }
        impl Drop for Cleanup {
            fn drop(&mut self) {
                self.release.notify_one();
                self.signal.trigger_immediate();
            }
        }

        let runtime = if workers == 1 {
            RuntimeBuilder::current_thread().build().expect("current-thread runtime")
        } else {
            RuntimeBuilder::multi_thread()
                .worker_threads(workers)
                .build()
                .expect("multi-worker runtime")
        };
        let runtime_handle = runtime.handle();
        runtime.block_on(async move {
            let cx = Cx::current().expect("runtime context");
            let owner_region = if owned {
                Some(
                    cx.open_child_region(ChildRegionSpec::inherit())
                        .await
                        .expect("open listener owner"),
                )
            } else {
                None
            };
            let owner = owner_region.as_ref().map(|region| region.cx().clone());
            let started = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let completed = Arc::new(AtomicBool::new(false));
            let started_for_handler = Arc::clone(&started);
            let release_for_handler = Arc::clone(&release);
            let completed_for_handler = Arc::clone(&completed);
            let handler = move |_request: Request| {
                let started = Arc::clone(&started_for_handler);
                let release = Arc::clone(&release_for_handler);
                let completed = Arc::clone(&completed_for_handler);
                async move {
                    let mut released = core::pin::pin!(release.notified());
                    let mut witnessed_pending = false;
                    std::future::poll_fn(|task| {
                        let result = released.as_mut().poll(task);
                        if result.is_pending() && !witnessed_pending {
                            witnessed_pending = true;
                            started.notify_one();
                        }
                        result
                    })
                    .await;
                    completed.store(true, Ordering::Release);
                    Response::new(200, "OK", b"request-completed-before-error".to_vec())
                }
            };
            let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind ingress");
            let address = tcp.local_addr().expect("ingress address");
            let queue = Arc::new(HandoffQueue::default());
            let config = Http2ListenerConfig::default()
                .host_policy(HostPolicy::allow_list(vec!["localhost".to_owned()]))
                .drain_timeout(Duration::from_secs(5))
                .hard_drain_timeout(WATCHDOG);
            let mut handoff_ingress = None;
            let listener = if fail_spawn {
                Http2Listener::from_listener(tcp, handler, config)
            } else {
                handoff_ingress = Some(tcp);
                Http2Listener::from_handoff(Arc::clone(&queue), handler, config)
            };
            let manager = listener.connection_manager().clone();
            let signal = listener.shutdown_signal();
            let requests = listener.in_flight_requests();
            let stats = listener.stats_handle();
            let _cleanup = Cleanup {
                release: Arc::clone(&release),
                signal: signal.clone(),
            };
            let spawn_attempts = Arc::new(AtomicUsize::new(0));
            let attempts_for_run = Arc::clone(&spawn_attempts);
            let mut serving = cx
                .spawn(move |_coordinator| async move {
                    if fail_spawn {
                        let spawner = owner.clone();
                        let runtime_for_spawn = runtime_handle.clone();
                        listener
                            .run_mapped_with(
                                owner,
                                runtime_handle,
                                move |connection| {
                                    if attempts_for_run.fetch_add(1, Ordering::AcqRel) == 1 {
                                        return Err(SpawnError::RuntimeUnavailable);
                                    }
                                    if let Some(spawner) = &spawner {
                                        spawner
                                            .spawn(move |_connection_cx| connection)
                                            .map(H2ConnectionTask::Owned)
                                    } else {
                                        runtime_for_spawn
                                            .try_spawn(connection)
                                            .map(H2ConnectionTask::Root)
                                    }
                                },
                                true,
                                #[cfg(feature = "http2-streaming")]
                                None,
                                |handler, request| async move {
                                    H2DispatchResponse::Buffered(
                                        handler(request).await.into_h2_response(),
                                    )
                                },
                            )
                            .await
                    } else if let Some(owner) = owner {
                        listener.run_in(&owner).await
                    } else {
                        listener.run(&runtime_handle).await
                    }
                })
                .expect("spawn listener coordinator");

            let mut client = TcpStream::connect(address).await.expect("connect request");
            if let Some(ingress) = handoff_ingress.take() {
                let (accepted, peer) = ingress.accept().await.expect("accept handoff");
                queue.push(HandoffStream::new(Box::new(accepted)), Some(peer));
            }
            let mut outbound = BytesMut::new();
            outbound.extend_from_slice(CLIENT_PREFACE);
            Frame::Settings(SettingsFrame::new(Vec::new()))
                .encode(&mut outbound)
                .expect("encode peer settings");
            Frame::Headers(HeadersFrame::new(
                1,
                encode_hpack_test_headers(&[
                    (":method", "GET"),
                    (":scheme", "http"),
                    (":path", "/drain"),
                    (":authority", "localhost"),
                ]),
                true,
                true,
            ))
            .encode(&mut outbound)
            .expect("encode request headers");
            client.write_all(&outbound).await.expect("write request");
            crate::time::timeout(cx.now(), WATCHDOG, started.notified())
                .await
                .expect("handler reaches a registered Pending");
            assert_eq!(manager.active_count(), 1);
            assert_eq!(requests.load(Ordering::Acquire), 1);
            assert!(!completed.load(Ordering::Acquire));

            let mut rejected = if fail_spawn {
                Some(TcpStream::connect(address).await.expect("second connection"))
            } else {
                queue.close();
                None
            };
            crate::time::timeout(cx.now(), WATCHDOG, async {
                while stats.snapshot().drains_started_total == 0 {
                    assert!(
                        !serving.is_finished(),
                        "fatal error was published before existing work entered drain"
                    );
                    yield_now().await;
                }
            })
            .await
            .expect("fatal accept or spawn failure starts the drain");
            assert_eq!(signal.phase(), ShutdownPhase::Draining);
            assert!(!serving.is_finished(), "the held handler still belongs to run");
            assert_eq!(manager.active_count(), 1, "rejected spawn released its guard");
            assert_eq!(requests.load(Ordering::Acquire), 1);
            if let Some(rejected) = rejected.as_mut() {
                let mut byte = [0_u8; 1];
                assert_eq!(
                    crate::time::timeout(cx.now(), WATCHDOG, rejected.read(&mut byte))
                        .await
                        .expect("rejected connection closes")
                        .expect("read rejected connection"),
                    0
                );
            }

            release.notify_one();
            let mut response = Vec::new();
            crate::time::timeout(cx.now(), WATCHDOG, client.read_to_end(&mut response))
                .await
                .expect("in-flight response and GOAWAY drain")
                .expect("read drained response");
            let mut response = {
                let mut bytes = BytesMut::new();
                bytes.extend_from_slice(&response);
                bytes
            };
            let mut codec = FrameCodec::new();
            let mut hpack = crate::http::h2::HpackDecoder::new();
            let mut status_ok = false;
            let mut end_stream = false;
            let mut definitive_goaway = false;
            let mut body = Vec::new();
            while let Some(frame) = codec.decode(&mut response).expect("decode drained frames") {
                match frame {
                    Frame::Headers(mut headers) => {
                        assert_eq!(headers.stream_id, 1);
                        assert!(headers.end_headers);
                        status_ok |= hpack
                            .decode(&mut headers.header_block)
                            .expect("decode response headers")
                            .contains(&Header::new(":status", "200"));
                        end_stream |= headers.end_stream;
                    }
                    Frame::Data(data) => {
                        assert_eq!(data.stream_id, 1);
                        body.extend_from_slice(&data.data);
                        end_stream |= data.end_stream;
                    }
                    Frame::GoAway(goaway) => {
                        assert_eq!(goaway.error_code, ErrorCode::NoError);
                        definitive_goaway |= goaway.last_stream_id == 1;
                    }
                    Frame::Settings(_) | Frame::WindowUpdate(_) => {}
                    other => panic!("unexpected frame during graceful drain: {other:?}"),
                }
            }
            assert!(response.is_empty(), "drain must not truncate a frame");
            assert!(status_ok);
            assert!(end_stream, "the response reaches END_STREAM");
            assert!(definitive_goaway, "the connection reaches definitive GOAWAY");
            assert_eq!(body, b"request-completed-before-error");

            let error = crate::time::timeout(cx.now(), WATCHDOG, serving.join(&cx))
                .await
                .expect("listener joins every connection")
                .expect("listener retains its typed result")
                .expect_err("original fatal error survives cleanup");
            if fail_spawn {
                assert_eq!(error.kind(), io::ErrorKind::Other);
                assert_eq!(
                    error.to_string(),
                    format!(
                        "failed to spawn h2 connection task: {}",
                        SpawnError::RuntimeUnavailable
                    )
                );
                assert_eq!(spawn_attempts.load(Ordering::Acquire), 2);
            } else {
                assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
                assert_eq!(error.to_string(), "HTTP handoff queue is closed");
            }
            assert_eq!(error.raw_os_error(), None);
            assert!(completed.load(Ordering::Acquire));
            assert_eq!(signal.phase(), ShutdownPhase::Stopped);
            assert!(manager.is_empty());
            assert_eq!(requests.load(Ordering::Acquire), 0);
            let snapshot = stats.snapshot();
            assert_eq!(snapshot.accepted_total, if fail_spawn { 2 } else { 1 });
            assert_eq!(snapshot.spawn_failures_total, u64::from(fail_spawn));
            assert_eq!(snapshot.transient_accept_errors_total, 0);
            assert_eq!(snapshot.drains_started_total, 1);
            assert_eq!(snapshot.drains_quiescent_total, 1);
            assert_eq!(snapshot.drain_escalations_total, 0);
            assert_eq!(snapshot.drain_hard_deadline_hits_total, 0);
            assert_eq!(snapshot.last_drain_requests_at_start, 1);
            assert_eq!(snapshot.last_drain_requests_stranded, 0);
            if let Some(region) = owner_region {
                crate::time::timeout(cx.now(), WATCHDOG, region.close())
                    .await
                    .expect("owner closes within bound")
                    .expect("owner reaches quiescence");
            }
        });
        let retired_at = std::time::Instant::now();
        while !runtime.is_quiescent() {
            assert!(retired_at.elapsed() < WATCHDOG, "listener work must retire");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(WATCHDOG));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn fatal_handoff_accept_error_drains_native_http2_requests() {
        for owned in [false, true] {
            for workers in [1, 2] {
                fatal_listener_failure_drains_request(false, owned, workers);
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn fatal_connection_spawn_error_drains_native_http2_requests() {
        for owned in [false, true] {
            for workers in [1, 2] {
                fatal_listener_failure_drains_request(true, owned, workers);
            }
        }
    }
