    use super::*;
    use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
    use crate::net::websocket::{
        Message, WebSocket, WebSocketConfig, WebSocketRead, WebSocketWrite,
    };
    use crate::time::VirtualClock;
    #[cfg(not(target_arch = "wasm32"))]
    use crate::time::{TimeSource, WallClock};
    use crate::types::{Budget, RegionId, TaskId};
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
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

    fn deadline_at(cx: &Cx, millis: u64) -> Option<HeartbeatDeadline> {
        Some(HeartbeatDeadline {
            at: Time::from_millis(millis),
            clock: cx.timer_driver(),
        })
    }

    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }

    #[test]
    fn a_ready_wait_releases_its_deadline_timer() {
        let clock = Arc::new(VirtualClock::new());
        let cx = timed_cx(&clock);
        let driver = cx.timer_driver().expect("timer driver");
        let probe = driver.clone();
        let io = std::pin::pin!(poll_fn(move |_| {
            assert_eq!(
                probe.pending_count(),
                1,
                "the deadline is armed before the I/O"
            );
            Poll::Ready(Ok::<_, WsError>(7_u8))
        }));
        let wait = std::pin::pin!(wait_until(&cx, deadline_at(&cx, 10), io));
        assert!(matches!(poll_once(wait), Poll::Ready(Ok(Some(7)))));
        assert_eq!(driver.pending_count(), 0);
    }

    #[test]
    fn pending_io_arms_the_timer_and_its_deadline_still_fires() {
        let clock = Arc::new(VirtualClock::new());
        let cx = timed_cx(&clock);
        let driver = cx.timer_driver().expect("timer driver");
        let io = std::pin::pin!(std::future::pending::<Result<u8, WsError>>());
        let mut wait = std::pin::pin!(wait_until(&cx, deadline_at(&cx, 10), io));
        assert!(poll_once(wait.as_mut()).is_pending());
        assert_eq!(driver.pending_count(), 1);
        clock.advance(20_000_000);
        assert_eq!(driver.process_timers(), 1, "the heartbeat deadline fires");
        assert!(matches!(poll_once(wait.as_mut()), Poll::Ready(Ok(None))));
    }

    #[test]
    fn a_due_deadline_wins_over_ready_io() {
        let clock = Arc::new(VirtualClock::new());
        let cx = timed_cx(&clock);
        clock.advance(20_000_000);
        let io = std::pin::pin!(std::future::ready(Ok::<_, WsError>(7_u8)));
        let wait = std::pin::pin!(wait_until(&cx, deadline_at(&cx, 10), io));
        assert!(matches!(poll_once(wait), Poll::Ready(Ok(None))));
    }

    #[test]
    fn cancellation_comes_before_ready_io() {
        let clock = Arc::new(VirtualClock::new());
        let cx = timed_cx(&clock);
        cx.set_cancel_requested(true);
        let io = std::pin::pin!(poll_fn(|_| -> Poll<Result<u8, WsError>> {
            panic!("cancelled I/O was polled")
        }));
        let wait = std::pin::pin!(wait_until(&cx, None, io));
        assert!(matches!(
            poll_once(wait),
            Poll::Ready(Err(WsError::Io(error))) if error.kind() == io::ErrorKind::Interrupted
        ));
    }

    #[test]
    fn cancellation_while_pending_wakes_and_interrupts() {
        let clock = Arc::new(VirtualClock::new());
        let cx = timed_cx(&clock);
        let io = std::pin::pin!(std::future::pending::<Result<u8, WsError>>());
        let mut wait = std::pin::pin!(wait_until(&cx, None, io));
        assert!(poll_once(wait.as_mut()).is_pending());
        cx.set_cancel_requested(true);
        assert!(matches!(
            poll_once(wait.as_mut()),
            Poll::Ready(Err(WsError::Io(error))) if error.kind() == io::ErrorKind::Interrupted
        ));
    }

    const INTERVAL_NS: u64 = 10_000_000;
    const READ_NS: u64 = 1_000_000;

    #[derive(Default)]
    struct Written {
        bytes: Vec<u8>,
        first_at: Option<Time>,
    }

    /// Reads and writes that are always ready, so `wait_until` never arms its
    /// timer and only `Heartbeat::update` can see a deadline pass. Each read
    /// delivers one binary frame and takes `READ_NS`; a write takes `write_ns`.
    struct ReadyIo {
        clock: Arc<VirtualClock>,
        timer: TimerDriverHandle,
        write_ns: u64,
        written: Arc<Mutex<Written>>,
    }

    impl AsyncRead for ReadyIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.clock.advance(READ_NS);
            buf.put_slice(&[0x82, 0x01, 0x07]);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ReadyIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut written = self.written.lock().expect("written");
            let now = self.timer.now();
            written.first_at.get_or_insert(now);
            written.bytes.extend_from_slice(data);
            self.clock.advance(self.write_ns);
            Poll::Ready(Ok(data.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Runs a future over ready I/O, through any `yield_now` on the way.
    fn drive<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        for _ in 0..16 {
            if let Poll::Ready(output) = poll_once(future.as_mut()) {
                return output;
            }
        }
        panic!("ready I/O did not finish");
    }

    enum Connection {
        Whole(WebSocket<ReadyIo>),
        Split(WebSocketRead<ReadyIo>, WebSocketWrite<ReadyIo>),
    }

    impl Connection {
        fn recv(&mut self, cx: &Cx) -> Result<Option<Message>, WsError> {
            match self {
                Self::Whole(ws) => drive(ws.recv(cx)),
                Self::Split(read, _) => drive(read.recv(cx)),
            }
        }

        fn send(&mut self, cx: &Cx, message: Message) -> Result<(), WsError> {
            match self {
                Self::Whole(ws) => drive(ws.send(cx, message)),
                Self::Split(_, write) => drive(write.send(cx, message)),
            }
        }
    }

    struct Scene {
        connection: Connection,
        cx: Cx,
        timer: TimerDriverHandle,
        written: Arc<Mutex<Written>>,
    }

    fn scene(split: bool, write_ns: u64) -> Scene {
        let clock = Arc::new(VirtualClock::new());
        let cx = timed_cx(&clock);
        let timer = cx.timer_driver().expect("timer driver");
        let written = Arc::new(Mutex::new(Written::default()));
        let io = ReadyIo {
            clock,
            timer: timer.clone(),
            write_ns,
            written: Arc::clone(&written),
        };
        let config = WebSocketConfig::new().ping_interval(Some(Duration::from_nanos(INTERVAL_NS)));
        let ws = WebSocket::from_upgraded(io, config);
        let connection = if split {
            let (read, write) = ws.split();
            Connection::Split(read, write)
        } else {
            Connection::Whole(ws)
        };
        Scene {
            connection,
            cx,
            timer,
            written,
        }
    }

    /// Receives until something other than a message comes back.
    fn recv_past_messages(scene: &mut Scene) -> Result<Option<Message>, WsError> {
        for _ in 0..200 {
            match scene.connection.recv(&scene.cx) {
                Ok(Some(_)) => {}
                other => return other,
            }
        }
        panic!("200 ready reads and the heartbeat never ended the connection");
    }

    fn assert_timed_out<T: std::fmt::Debug>(result: &Result<T, WsError>, what: &str) {
        assert!(
            matches!(result, Err(WsError::Io(error)) if error.kind() == io::ErrorKind::TimedOut),
            "{what}: {result:?}"
        );
    }

    fn silent_peer_times_out_within_one_read(split: bool) {
        let mut scene = scene(split, 0);
        let outcome = recv_past_messages(&mut scene);
        assert_timed_out(&outcome, "the deadline ends the connection");
        let pinged = scene.written.lock().expect("written").first_at;
        let limit = pinged.expect("the Ping went out").as_nanos() + INTERVAL_NS + READ_NS;
        let now = scene.timer.now().as_nanos();
        assert!(now <= limit, "expired at {now}, limit {limit}");
    }

    #[test]
    fn a_silent_peer_behind_always_ready_reads_times_out_within_one_read_whole() {
        silent_peer_times_out_within_one_read(false);
    }

    #[test]
    fn a_silent_peer_behind_always_ready_reads_times_out_within_one_read_split() {
        silent_peer_times_out_within_one_read(true);
    }

    fn scheduled_ping_goes_out(split: bool) {
        let mut scene = scene(split, 0);
        for _ in 0..30 {
            if !scene.written.lock().expect("written").bytes.is_empty() {
                break;
            }
            let message = scene.connection.recv(&scene.cx).expect("recv");
            assert!(message.is_some(), "the flood keeps arriving");
        }
        let written = scene.written.lock().expect("written");
        assert_eq!(written.bytes.first(), Some(&0x89), "a Ping frame");
        let sent = written.first_at.expect("the Ping went out").as_nanos();
        let limit = INTERVAL_NS + READ_NS;
        assert!(sent <= limit, "sent at {sent}, limit {limit}");
    }

    #[test]
    fn a_scheduled_ping_goes_out_under_always_ready_reads_whole() {
        scheduled_ping_goes_out(false);
    }

    #[test]
    fn a_scheduled_ping_goes_out_under_always_ready_reads_split() {
        scheduled_ping_goes_out(true);
    }

    fn ready_write_cannot_skip_a_failed_heartbeat(split: bool) {
        // The Ping's write reports ready three intervals later.
        let mut scene = scene(split, 3 * INTERVAL_NS);
        let outcome = recv_past_messages(&mut scene);
        assert_timed_out(&outcome, "the next update ends the connection");
        let wire = scene.written.lock().expect("written").bytes.len();
        let data = scene.connection.send(&scene.cx, Message::binary(vec![1]));
        assert!(
            matches!(&data, Err(WsError::Io(error)) if error.kind() == io::ErrorKind::NotConnected),
            "the closed handshake refuses data: {data:?}"
        );
        // A control frame passes the closed check, so only the latch stops it.
        let ping = Message::Ping(Bytes::copy_from_slice(b"late"));
        let control = scene.connection.send(&scene.cx, ping);
        assert_timed_out(&control, "a failed heartbeat refuses later writes");
        assert_eq!(
            scene.written.lock().expect("written").bytes.len(),
            wire,
            "nothing reaches the wire after a failed heartbeat"
        );
        let after = scene.connection.recv(&scene.cx);
        assert!(
            !matches!(after, Ok(Some(_))),
            "no message comes after a failed heartbeat"
        );
    }

    #[test]
    fn an_always_ready_write_past_the_deadline_cannot_skip_a_failed_heartbeat_whole() {
        ready_write_cannot_skip_a_failed_heartbeat(false);
    }

    #[test]
    fn an_always_ready_write_past_the_deadline_cannot_skip_a_failed_heartbeat_split() {
        ready_write_cannot_skip_a_failed_heartbeat(true);
    }
