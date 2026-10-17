    use super::*;
    use crate::time::VirtualClock;
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
    fn heartbeat_retains_wall_clock_under_foreign_ambient_and_resumed_context() {
        let explicit = Cx::for_testing();
        let foreign = timed_cx(&Arc::new(VirtualClock::starting_at(Time::from_secs(
            1_000_000,
        ))));
        let interval = Duration::from_secs(60);
        let mut heartbeat = Heartbeat::default();
        let before = heartbeat.now();
        let _ambient = Cx::set_current(Some(foreign.clone()));
        assert!(
            heartbeat
                .update(&explicit, Some(interval), true, false)
                .unwrap()
                .is_none()
        );
        let after = heartbeat.now();
        let deadline = heartbeat.deadline().unwrap();
        assert!(deadline.at >= before + interval && deadline.at <= after + interval);
        assert!(
            heartbeat
                .update(&foreign, Some(interval), true, false)
                .unwrap()
                .is_none()
        );
        assert!(heartbeat.clock.is_none(), "first receive chose wall clock");
        let mut wait = std::pin::pin!(wait_until(
            &foreign,
            Some(deadline),
            std::future::pending::<Result<(), WsError>>()
        ));
        assert!(
            wait.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "a foreign virtual clock cannot expire the retained wall deadline"
        );
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
            let mut wait = std::pin::pin!(wait_until(
                &foreign,
                heartbeat.deadline(),
                std::future::pending::<Result<(), WsError>>()
            ));
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            clock.advance(1_000_000);
            assert!(matches!(
                wait.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Ok(None))
            ));
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
