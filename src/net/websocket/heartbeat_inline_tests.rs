    use super::*;
    use crate::time::VirtualClock;
    #[cfg(not(target_arch = "wasm32"))]
    use crate::time::{TimeSource, WallClock};
    use crate::types::{Budget, RegionId, TaskId};
    use std::sync::Arc;
    use std::task::{Context, Waker};

    fn timed_cx(clock: &Arc<VirtualClock>) -> Cx {
        Cx::new_with_drivers(
            RegionId::new_for_test(1, 0),
            TaskId::new_for_test(1, 0),
            Budget::INFINITE,
            None,
            None,
            None,
            Some(TimerDriverHandle::with_virtual_clock(Arc::clone(clock))),
            None,
        )
    }

    #[test]
    fn heartbeat_wait_storage_does_not_scale_with_the_pinned_operation() {
        struct InlineOperation<const N: usize>([u8; N]);

        impl<const N: usize> Future for InlineOperation<N> {
            type Output = Result<u8, WsError>;

            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
                Poll::Ready(Ok(self.0[0]))
            }
        }

        let cx = Cx::for_testing();
        let mut small = std::pin::pin!(InlineOperation([7; 1]));
        let mut large = std::pin::pin!(InlineOperation([7; 16 * 1024]));
        let small_wait = wait_until(&cx, None, small.as_mut());
        let large_wait = wait_until(&cx, None, large.as_mut());
        assert_eq!(
            std::mem::size_of_val(&small_wait),
            std::mem::size_of_val(&large_wait),
            "heartbeat bookkeeping must not retain inline operation storage"
        );
        assert!(matches!(
            std::pin::pin!(small_wait).poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(Some(7)))
        ));
        assert!(matches!(
            std::pin::pin!(large_wait).poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(Some(7)))
        ));
    }

    #[test]
    fn heartbeat_wait_keeps_pinned_operation_alive_and_preserves_stop_priority() {
        use std::cell::Cell;
        use std::marker::PhantomPinned;

        struct Operation<'a> {
            ready: &'a Cell<bool>,
            polls: &'a Cell<usize>,
            drops: &'a Cell<usize>,
            _pin: PhantomPinned,
        }

        impl Future for Operation<'_> {
            type Output = Result<u8, WsError>;

            fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
                self.polls.set(self.polls.get() + 1);
                if self.ready.get() {
                    Poll::Ready(Ok(7))
                } else {
                    Poll::Pending
                }
            }
        }

        impl Drop for Operation<'_> {
            fn drop(&mut self) {
                self.drops.set(self.drops.get() + 1);
            }
        }

        let ready = Cell::new(false);
        let polls = Cell::new(0);
        let drops = Cell::new(0);
        let mut operation = Box::pin(Operation {
            ready: &ready,
            polls: &polls,
            drops: &drops,
            _pin: PhantomPinned,
        });
        let cx = Cx::for_testing();
        let mut task = Context::from_waker(Waker::noop());
        {
            let mut wait = std::pin::pin!(wait_until(&cx, None, operation.as_mut()));
            assert!(wait.as_mut().poll(&mut task).is_pending());
        }
        assert_eq!(polls.get(), 1);
        assert_eq!(drops.get(), 0, "dropping a wait drops only its borrow");

        ready.set(true);
        let clock = Arc::new(VirtualClock::new());
        let timed = timed_cx(&clock);
        let expired = || HeartbeatDeadline {
            at: Time::ZERO,
            clock: timed.timer_driver(),
        };
        {
            let mut wait = std::pin::pin!(wait_until(
                &timed,
                Some(expired()),
                operation.as_mut()
            ));
            assert!(matches!(
                wait.as_mut().poll(&mut task),
                Poll::Ready(Ok(None))
            ));
        }
        assert_eq!(polls.get(), 1, "an expired deadline precedes ready I/O");

        timed.set_cancel_requested(true);
        {
            let mut wait = std::pin::pin!(wait_until(
                &timed,
                Some(expired()),
                operation.as_mut()
            ));
            assert!(matches!(
                wait.as_mut().poll(&mut task),
                Poll::Ready(Err(WsError::Io(error)))
                    if error.kind() == io::ErrorKind::Interrupted
            ));
        }
        assert_eq!(polls.get(), 1, "cancellation precedes the deadline and I/O");
        assert_eq!(drops.get(), 0);

        {
            let mut wait = std::pin::pin!(wait_until(&cx, None, operation.as_mut()));
            assert!(matches!(
                wait.as_mut().poll(&mut task),
                Poll::Ready(Ok(Some(7)))
            ));
        }
        assert_eq!(polls.get(), 2);
        drop(operation);
        assert_eq!(drops.get(), 1);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn heartbeat_retains_wall_clock_under_foreign_ambient_and_resumed_context() {
        let explicit = Cx::for_testing();
        let foreign = timed_cx(&Arc::new(VirtualClock::starting_at(Time::from_secs(
            1_000_000,
        ))));
        let interval = Duration::from_secs(60);
        let mut heartbeat = Heartbeat::default();
        let wall = WallClock::new();
        let before = wall.now();
        let _ambient = Cx::set_current(Some(foreign.clone()));
        assert!(
            heartbeat
                .update(&explicit, Some(interval), true, false)
                .unwrap()
                .is_none()
        );
        let after = wall.now();
        let deadline = heartbeat.deadline().unwrap();
        assert!(foreign.timer_driver().unwrap().now() > after + interval);
        assert!(deadline.at >= before + interval && deadline.at <= after + interval);
        assert!(
            heartbeat
                .update(&foreign, Some(interval), true, false)
                .unwrap()
                .is_none()
        );
        assert!(heartbeat.clock.is_none(), "first receive chose wall clock");
        heartbeat.note_read();
        assert!(heartbeat.last_read.unwrap() >= before);
        assert!(heartbeat.last_read.unwrap() <= wall.now());
        let mut operation = std::pin::pin!(std::future::pending::<Result<(), WsError>>());
        let mut wait = std::pin::pin!(wait_until(
            &foreign,
            Some(deadline),
            operation.as_mut()
        ));
        assert!(
            wait.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "a foreign virtual clock cannot expire the retained wall deadline"
        );
        assert_eq!(foreign.timer_driver().unwrap().pending_count(), 0);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn heartbeat_wall_wait_ignores_later_timer_epochs_but_honors_its_cancellation_owner() {
        let wall = WallClock::new();
        let ahead = Time::from_secs(1_000_000);
        for (owner_epoch, ambient_epoch) in [(Time::ZERO, ahead), (ahead, Time::ZERO)] {
            let owner = timed_cx(&Arc::new(VirtualClock::starting_at(owner_epoch)));
            let ambient = timed_cx(&Arc::new(VirtualClock::starting_at(ambient_epoch)));
            let owner_timer = owner.timer_driver().unwrap();
            let ambient_timer = ambient.timer_driver().unwrap();
            let deadline = HeartbeatDeadline {
                at: wall.now() + Duration::from_secs(60),
                clock: None,
            };
            assert!(deadline.at < ahead, "virtual epochs straddle the wall deadline");
            ambient.set_cancel_requested(true);
            let _ambient = Cx::set_current(Some(ambient.clone()));
            let mut operation = std::pin::pin!(std::future::pending::<Result<(), WsError>>());
            let mut wait = std::pin::pin!(wait_until(
                &owner,
                Some(deadline),
                operation.as_mut()
            ));
            let mut task = Context::from_waker(Waker::noop());
            assert!(
                wait.as_mut().poll(&mut task).is_pending(),
                "neither a foreign epoch nor ambient cancellation ends the wall wait"
            );
            assert_eq!(owner_timer.pending_count(), 0);
            assert_eq!(ambient_timer.pending_count(), 0);

            owner.set_cancel_requested(true);
            assert!(matches!(
                wait.as_mut().poll(&mut task),
                Poll::Ready(Err(WsError::Io(error)))
                    if error.kind() == io::ErrorKind::Interrupted
            ));
            assert_eq!(owner_timer.pending_count(), 0);
            assert_eq!(ambient_timer.pending_count(), 0);
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn heartbeat_wall_deadline_expires_while_a_later_virtual_clock_is_behind() {
        let owner = timed_cx(&Arc::new(VirtualClock::new()));
        let foreign = timed_cx(&Arc::new(VirtualClock::starting_at(Time::from_secs(
            1_000_000,
        ))));
        let wall = WallClock::new();
        let at = wall.now();
        assert!(at > owner.timer_driver().unwrap().now());
        let _ambient = Cx::set_current(Some(foreign.clone()));
        let mut operation = std::pin::pin!(std::future::pending::<Result<(), WsError>>());
        let mut wait = std::pin::pin!(wait_until(
            &owner,
            Some(HeartbeatDeadline { at, clock: None }),
            operation.as_mut()
        ));
        assert!(matches!(
            wait.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(None))
        ));
        assert_eq!(owner.timer_driver().unwrap().pending_count(), 0);
        assert_eq!(foreign.timer_driver().unwrap().pending_count(), 0);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn heartbeat_wall_clock_survives_split_reunite_and_changed_receivers() {
        use crate::net::websocket::{WebSocket, WebSocketConfig};

        let original = Cx::for_testing();
        let ahead = timed_cx(&Arc::new(VirtualClock::starting_at(Time::from_secs(
            1_000_000,
        ))));
        let behind = timed_cx(&Arc::new(VirtualClock::new()));
        let (io, _peer) = crate::io::duplex(64);
        let mut websocket = WebSocket::from_upgraded(
            io,
            WebSocketConfig {
                ping_interval: Some(Duration::from_secs(60)),
                ..WebSocketConfig::default()
            },
        );
        let mut task = Context::from_waker(Waker::noop());
        {
            let _ambient = Cx::set_current(Some(original.clone()));
            let mut recv = std::pin::pin!(websocket.recv(&original));
            assert!(recv.as_mut().poll(&mut task).is_pending());
        }
        let at = websocket.heartbeat.deadline().unwrap().at;
        let (mut read, write) = websocket.split();
        {
            let _ambient = Cx::set_current(Some(ahead.clone()));
            let mut recv = std::pin::pin!(read.recv(&ahead));
            assert!(recv.as_mut().poll(&mut task).is_pending());
            assert_eq!(ahead.timer_driver().unwrap().pending_count(), 0);
        }
        let mut websocket = read.reunite(write).expect("the dropped receive releases its borrow");
        assert!(websocket.heartbeat.clock.is_none());
        assert_eq!(websocket.heartbeat.deadline().unwrap().at, at);
        {
            let _ambient = Cx::set_current(Some(behind.clone()));
            let mut recv = std::pin::pin!(websocket.recv(&behind));
            assert!(recv.as_mut().poll(&mut task).is_pending());
            assert_eq!(behind.timer_driver().unwrap().pending_count(), 0);
        }
        assert!(websocket.heartbeat.clock.is_none());
        assert_eq!(websocket.heartbeat.deadline().unwrap().at, at);
    }

    #[test]
    fn zero_interval_uses_a_real_deadline_and_late_pong_cannot_rearm() {
        let clock = Arc::new(VirtualClock::new());
        let cx = timed_cx(&clock);
        let foreign = timed_cx(&Arc::new(VirtualClock::starting_at(Time::from_secs(
            1_000_000,
        ))));
        let _ambient = Cx::set_current(Some(foreign.clone()));
        let mut heartbeat = Heartbeat::default();
        assert!(
            heartbeat
                .update(&cx, Some(Duration::ZERO), true, false)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            heartbeat.deadline().unwrap().at,
            Time::from_nanos(1_000_000)
        );
        {
            let mut operation = std::pin::pin!(std::future::pending::<Result<(), WsError>>());
            let mut wait = std::pin::pin!(wait_until(
                &foreign,
                heartbeat.deadline(),
                operation.as_mut()
            ));
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            assert_eq!(cx.timer_driver().unwrap().pending_count(), 1);
            assert_eq!(foreign.timer_driver().unwrap().pending_count(), 0);
            clock.advance(1_000_000);
            assert!(matches!(
                wait.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Ok(None))
            ));
            assert_eq!(cx.timer_driver().unwrap().pending_count(), 0);
            assert_eq!(foreign.timer_driver().unwrap().pending_count(), 0);
        }
        let payload = heartbeat
            .update(&foreign, Some(Duration::ZERO), true, false)
            .unwrap()
            .unwrap();
        heartbeat.ping_queued();
        heartbeat.received_pong(b"unrelated");
        clock.advance(1_000_000);
        heartbeat.received_pong(&payload);
        assert!(
            matches!(heartbeat.update(&cx, Some(Duration::ZERO), true, false), Err(WsError::Io(error)) if error.kind() == io::ErrorKind::TimedOut),
            "a matching Pong at the deadline is late, even after thread preemption"
        );
    }

    /// A Pong is judged by when it reached the read buffer, not by when the
    /// application next calls recv to decode it (asupersync-5aioka item 4).
    #[test]
    fn a_pong_read_in_time_counts_although_it_is_decoded_after_the_deadline() {
        let clock = Arc::new(VirtualClock::new());
        let cx = timed_cx(&clock);
        let interval = Duration::from_millis(10);
        let ms = |n: u64| n * 1_000_000;
        let mut heartbeat = Heartbeat::default();
        assert!(
            heartbeat
                .update(&cx, Some(interval), true, false)
                .unwrap()
                .is_none()
        );
        clock.advance(ms(10));
        let payload = heartbeat
            .update(&cx, Some(interval), true, false)
            .unwrap()
            .unwrap();
        heartbeat.ping_queued();
        // The Pong is read 1 ms after the Ping, behind a message the
        // application takes first; its next recv comes 50 ms later.
        clock.advance(ms(1));
        heartbeat.note_read();
        clock.advance(ms(50));
        assert!(
            heartbeat
                .update(&cx, Some(interval), true, true)
                .unwrap()
                .is_none(),
            "bytes read before the deadline are decoded before it can expire"
        );
        heartbeat.received_pong(&payload);
        assert!(
            heartbeat
                .update(&cx, Some(interval), true, false)
                .unwrap()
                .is_none()
        );
        assert!(
            !heartbeat.failed(),
            "the Pong read in time rearmed the heartbeat"
        );

        // Bytes read in time that hold no Pong: once the decoder finds no
        // complete frame left, the deadline fails.
        clock.advance(ms(10));
        let _second_ping = heartbeat
            .update(&cx, Some(interval), true, false)
            .unwrap()
            .unwrap();
        heartbeat.ping_queued();
        clock.advance(ms(1));
        heartbeat.note_read();
        clock.advance(ms(50));
        assert!(
            heartbeat
                .update(&cx, Some(interval), true, true)
                .unwrap()
                .is_none()
        );
        heartbeat.note_drained();
        assert!(
            matches!(heartbeat.update(&cx, Some(interval), true, true), Err(WsError::Io(error)) if error.kind() == io::ErrorKind::TimedOut),
            "no Pong among the bytes read in time"
        );

        // Bytes read after the deadline get no grace.
        let mut late = Heartbeat::default();
        assert!(
            late.update(&cx, Some(interval), true, false)
                .unwrap()
                .is_none()
        );
        clock.advance(ms(10));
        let payload = late
            .update(&cx, Some(interval), true, false)
            .unwrap()
            .unwrap();
        late.ping_queued();
        clock.advance(ms(20));
        late.note_read();
        assert!(
            matches!(late.update(&cx, Some(interval), true, true), Err(WsError::Io(error)) if error.kind() == io::ErrorKind::TimedOut),
            "a Pong read after the deadline is late"
        );
        late.received_pong(&payload);
        assert!(late.failed());
    }
