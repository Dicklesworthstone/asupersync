    use super::*;

    #[test]
    fn response_published_between_funnel_and_join_probes_precedes_retirement() {
        let cx = Cx::for_testing();
        let (terminal, receiver) = crate::channel::oneshot::channel();
        let task = TaskHandle::new(cx.task_id(), receiver, std::sync::Weak::new());
        let mut owners = H2RequestOwners {
            region: None,
            tasks: BTreeMap::from([(1, task)]),
            completed: None,
        };
        let (sender, mut receiver) = mpsc::channel(1);
        let mut terminal = Some(terminal);
        let mut received = std::pin::pin!(receiver.recv(&cx));
        let mut probes = 0;
        let mut response = std::pin::pin!(std::future::poll_fn(|task_cx| {
            probes += 1;
            let result = received.as_mut().poll(task_cx);
            if probes == 1 {
                assert!(result.is_pending(), "first funnel probe is genuinely empty");
                // Simulate the other worker publishing after our empty probe
                // and finishing before this poll reaches the join handle.
                assert!(
                    sender
                        .try_send(FunnelItem::Response {
                            stream_id: 1,
                            response: Response::new(200, "OK", Vec::new()).into_h2_response(),
                            guard: InFlightRequestGuard::acquire(None),
                            suppress_response_body: false,
                        })
                        .is_ok()
                );
                assert!(terminal.take().unwrap().send_blocking(Ok(())).is_ok());
            }
            result
        }));
        let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            owners.poll_event(response.as_mut(), &mut task_cx),
            Poll::Ready(DriverEvent::Response(FunnelItem::Response {
                stream_id: 1,
                ..
            }))
        ));
        assert!(
            owners.completed.is_some(),
            "terminal handle is consumed once and retained"
        );
        let mut empty = std::pin::pin!(std::future::pending());
        assert!(matches!(
            owners.poll_event(empty.as_mut(), &mut task_cx),
            Poll::Ready(DriverEvent::RequestRetired(1, Ok(())))
        ));
        owners.remove_completed(1);
        assert_eq!(owners.len(), 0);
    }

    #[test]
    fn producer_local_rejection_and_owner_cancel_both_start_bounded_drain() {
        use crate::time::{TimerDriverHandle, VirtualClock};
        use crate::types::{RegionId, TaskId};
        use std::sync::atomic::AtomicBool;

        struct Retirement(Arc<AtomicBool>);
        impl Drop for Retirement {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        for owner_cancel in [false, true] {
            let clock = Arc::new(VirtualClock::new());
            let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
            let owner = Cx::new_with_drivers(
                RegionId::new_for_test(1, 0),
                TaskId::new_for_test(1, 0),
                Budget::INFINITE,
                None,
                None,
                None,
                Some(timer.clone()),
                None,
            );
            let _ambient = Cx::set_current(Some(owner.clone()));
            let region = ServerRequestRegion::mint_from_connection(
                "h2-produced",
                Budget::INFINITE,
                Time::ZERO,
                &owner,
            );
            let producer_cx = region.cx().clone();
            let retired = Arc::new(AtomicBool::new(false));
            let retirement = Retirement(Arc::clone(&retired));
            let observed_cancel = Arc::new(AtomicBool::new(false));
            let observed_by_body = Arc::clone(&observed_cancel);
            // Deliberately never wakes itself and never finishes, even after
            // observing cancellation. The protocol drain must bound it.
            let producer = std::future::poll_fn(move |_| {
                let _retained = &retirement;
                if Cx::current().unwrap().is_cancel_requested() {
                    observed_by_body.store(true, Ordering::Release);
                }
                Poll::<()>::Pending
            });
            let run = region.run_with_protocol_drain(
                RequestBudgetSource::Inherited,
                Some(producer_cx.clone()),
                Duration::from_millis(10),
                producer,
            );
            let mut future = Box::pin(forward_h2_producer_cancellation(&owner, &producer_cx, run));
            let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(future.as_mut().poll(&mut task_cx).is_pending());
            if owner_cancel {
                owner.cancel_with(CancelKind::User, Some("connection owner cancelled"));
            } else {
                ProducedCancellationGuard::new(producer_cx.clone())
                    .cancel("locally rejected produced response body");
                assert!(!owner.is_cancel_requested());
            }
            assert!(future.as_mut().poll(&mut task_cx).is_pending());
            assert!(observed_cancel.load(Ordering::Acquire));
            assert!(!retired.load(Ordering::Acquire));
            clock.advance_to(Time::from_millis(10));
            assert!(timer.process_timers() > 0);
            assert!(matches!(
                future.as_mut().poll(&mut task_cx),
                Poll::Ready(ServerHopOutcome::ConnectionLost)
            ));
            drop(future);
            assert!(retired.load(Ordering::Acquire));
            assert_eq!(timer.pending_count(), 0);
        }
    }
