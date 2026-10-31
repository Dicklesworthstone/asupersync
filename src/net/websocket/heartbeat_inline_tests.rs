    use super::*;
    use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
    use crate::net::websocket::{
        Message, WebSocket, WebSocketConfig, WebSocketRead, WebSocketWrite,
    };
    use crate::time::VirtualClock;
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
    fn io_ready_at_once_arms_no_timer() {
        let clock = Arc::new(VirtualClock::new());
        let cx = timed_cx(&clock);
        let driver = cx.timer_driver().expect("timer driver");
        let probe = driver.clone();
        let io = poll_fn(move |_| {
            assert_eq!(probe.pending_count(), 0, "I/O comes before the timer");
            Poll::Ready(Ok::<_, WsError>(7_u8))
        });
        let wait = std::pin::pin!(wait_until(&cx, deadline_at(&cx, 10), io));
        assert!(matches!(poll_once(wait), Poll::Ready(Ok(Some(7)))));
        assert_eq!(driver.pending_count(), 0);
    }

    #[test]
    fn pending_io_arms_the_timer_and_its_deadline_still_fires() {
        let clock = Arc::new(VirtualClock::new());
        let cx = timed_cx(&clock);
        let driver = cx.timer_driver().expect("timer driver");
        let io = std::future::pending::<Result<u8, WsError>>();
        let mut wait = std::pin::pin!(wait_until(&cx, deadline_at(&cx, 10), io));
        assert!(poll_once(wait.as_mut()).is_pending());
        assert_eq!(driver.pending_count(), 1);
        clock.advance(20_000_000);
        driver.process_timers();
        assert!(matches!(poll_once(wait.as_mut()), Poll::Ready(Ok(None))));
    }

    #[test]
    fn ready_io_wins_over_a_due_deadline() {
        let clock = Arc::new(VirtualClock::new());
        let cx = timed_cx(&clock);
        clock.advance(20_000_000);
        let io = std::future::ready(Ok::<_, WsError>(7_u8));
        let wait = std::pin::pin!(wait_until(&cx, deadline_at(&cx, 10), io));
        assert!(matches!(poll_once(wait), Poll::Ready(Ok(Some(7)))));
    }

    #[test]
    fn cancellation_comes_before_ready_io() {
        let clock = Arc::new(VirtualClock::new());
        let cx = timed_cx(&clock);
        cx.set_cancel_requested(true);
        let io = poll_fn(|_| -> Poll<Result<u8, WsError>> { panic!("cancelled I/O was polled") });
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
        let io = std::future::pending::<Result<u8, WsError>>();
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
