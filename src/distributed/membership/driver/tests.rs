use super::*;
use crate::distributed::membership::{
    MemberState, MembershipEvent, MembershipKind, Packet, Payload, Rumor, decode_packet,
    encode_packet,
};
use std::collections::VecDeque;
use std::task::Waker;

#[test]
fn elapsed_rearm_keeps_tick_ready_without_repolling_completed_sleep() {
    use crate::time::VirtualClock;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    #[derive(Default)]
    struct Wakes(AtomicUsize);
    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    let clock = Arc::new(VirtualClock::new());
    let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut task = Context::from_waker(&waker);
    let tick = 5_000_000;
    let mut ticker = TickTimer::new(Time::from_nanos(tick), timer.clone());
    assert!(!ticker.poll_due(&mut task));
    assert_eq!(timer.pending_count(), 1);
    clock.advance(tick);
    assert_eq!(timer.process_timers(), 1);
    assert!(ticker.poll_due(&mut task));

    // The driver samples now before engine.turn. Move the real virtual clock
    // past the next deadline during that turn, before the timer is rearmed.
    // The old loop completed this Sleep at arm time, then panicked next poll.
    let sampled_now = timer.now();
    clock.advance(2 * tick);
    let elapsed_deadline = Time::from_nanos(sampled_now.as_nanos() + tick);
    let before = wakes.0.load(Ordering::Relaxed);
    ticker.rearm(elapsed_deadline, timer.clone(), &mut task);
    assert_eq!(wakes.0.load(Ordering::Relaxed), before + 1);
    assert_eq!(timer.pending_count(), 0);
    assert!(ticker.poll_due(&mut task));
    assert!(ticker.poll_due(&mut task));
    assert_eq!(wakes.0.load(Ordering::Relaxed), before + 1);

    // A later, future deadline clears the carried completion and really parks
    // again. Its timer fires once, and dropping a rearmed timer releases it.
    let future_deadline = Time::from_nanos(timer.now().as_nanos() + tick);
    ticker.rearm(future_deadline, timer.clone(), &mut task);
    assert!(!ticker.poll_due(&mut task));
    assert_eq!(timer.pending_count(), 1);
    clock.advance(tick);
    assert_eq!(timer.process_timers(), 1);
    assert!(ticker.poll_due(&mut task));
    ticker.rearm(
        Time::from_nanos(timer.now().as_nanos() + tick),
        timer.clone(),
        &mut task,
    );
    assert_eq!(timer.pending_count(), 1);
    drop(ticker);
    assert_eq!(timer.pending_count(), 0);
    eprintln!(
        "{}",
        serde_json::json!({
            "bead": "asupersync-bi2462.161",
            "scenario": "elapsed_swim_tick_rearm",
            "sampled_now_ns": sampled_now.as_nanos(),
            "rearm_deadline_ns": elapsed_deadline.as_nanos(),
            "now_ns": timer.now().as_nanos(),
            "ready_at_arm": true,
            "future_tick_fired": true,
            "pending_after_drop": timer.pending_count(),
        })
    );
}

fn node(name: &str) -> NodeId { NodeId::new(name) }
fn address(port: u16) -> SocketAddr { SocketAddr::from(([127, 0, 0, 1], port)) }
fn protocol() -> SwimConfig {
    SwimConfig { probe_interval_ms: 100, probe_timeout_ms: 20, awareness_max: 1,
        suspicion_mult: 1, suspicion_max_timeout_mult: 1, indirect_probe_count: 1,
        max_members: 8, ..SwimConfig::default() }
}
fn config() -> SwimDriverConfig {
    SwimDriverConfig { max_peers: 8, max_queued_datagrams: 16, retained_events: 2,
        io_batch: 4, tick_ms: 5, max_datagram_age_ms: 500, leave_timeout_ms: 50 }
}
fn make_engine(local: &str, peers: &[(&str, u16)]) -> Engine {
    let mut swim = Swim::new(node(local), protocol(), 7);
    let peers: BTreeMap<_, _> = peers.iter().map(|(id, port)| (node(id), address(*port))).collect();
    for peer in peers.keys() { swim.add_peer(0, peer.clone()); }
    swim.drain_events();
    Engine::new(swim, peers, 1400, config())
}
fn bytes(packet: Packet) -> Vec<u8> { encode_packet(&packet, 1400).unwrap().bytes }

#[derive(Default)]
struct Script {
    inbound: VecDeque<(SocketAddr, Vec<u8>)>,
    current: Vec<u8>,
    attempts: Vec<(SocketAddr, Vec<u8>)>,
    sent: Vec<(SocketAddr, Vec<u8>)>,
    blocked: bool,
    partial: bool,
    send_error: bool,
}
impl DatagramIo for Script {
    fn poll_datagram(&mut self, _: &mut Context<'_>) -> Poll<io::Result<(SocketAddr, &[u8])>> {
        match self.inbound.pop_front() {
            Some((from, bytes)) => { self.current = bytes; Poll::Ready(Ok((from, &self.current))) }
            None => Poll::Pending,
        }
    }
    fn poll_send_datagram(&mut self, _: &mut Context<'_>, target: SocketAddr, bytes: &[u8]) -> Poll<io::Result<usize>> {
        self.attempts.push((target, bytes.to_vec()));
        if self.blocked { return Poll::Pending; }
        if self.send_error { return Poll::Ready(Err(io::ErrorKind::ConnectionRefused.into())); }
        if self.partial { return Poll::Ready(Ok(bytes.len() - 1)); }
        self.sent.push((target, bytes.to_vec()));
        Poll::Ready(Ok(bytes.len()))
    }
}
fn turn(engine: &mut Engine, io: &mut Script, now: u64, tick: bool) -> Result<engine::Turn, SwimDriverError> {
    engine.turn(io, &mut Context::from_waker(Waker::noop()), now, tick)
}

#[test]
fn pending_send_retains_identical_datagram_and_resumes_without_false_accounting() {
    let mut engine = make_engine("a", &[("b", 2)]);
    let mut io = Script { blocked: true, ..Script::default() };
    assert_eq!(turn(&mut engine, &mut io, 0, true).unwrap(), engine::Turn::Park);
    assert_eq!(engine.outbox.len(), 1);
    assert_eq!(engine.stats.sent_datagrams, 0);
    let original = io.attempts[0].clone();
    turn(&mut engine, &mut io, 1, false).unwrap();
    assert_eq!(io.attempts[1], original);
    io.blocked = false;
    turn(&mut engine, &mut io, 2, false).unwrap();
    assert_eq!(io.sent, vec![original]);
    assert_eq!(engine.stats.sent_datagrams, 1);
    assert_eq!(engine.stats.sent_bytes, io.sent[0].1.len() as u64);
    assert!(engine.outbox.is_empty());
}

#[test]
fn send_backpressure_does_not_block_ack_receive_or_timeout_progress() {
    let mut engine = make_engine("a", &[("b", 2)]);
    let mut io = Script::default();
    turn(&mut engine, &mut io, 0, true).unwrap();
    let Payload::Ping { seq } = decode_packet(&io.sent[0].1).unwrap().payload else { panic!("first probe"); };
    // A real earlier probe was sent; an unrelated response now hits socket
    // backpressure while the original probe's acknowledgement arrives.
    io.blocked = true;
    io.inbound.push_back((address(2), bytes(Packet::new(Payload::Ping { seq: 100 }))));
    turn(&mut engine, &mut io, 1, false).unwrap();
    assert_eq!(engine.outbox.len(), 1);
    io.inbound.push_back((address(2), bytes(Packet::new(Payload::Ack { seq }))));
    turn(&mut engine, &mut io, 20, true).unwrap();
    assert_eq!(engine.stats.accepted_packets, 2);
    assert_eq!(engine.stats.received_acks, 1);
    assert_eq!(engine.stats.sent_datagrams, 1);
    turn(&mut engine, &mut io, 100, true).unwrap();
    assert_eq!(engine.swim.state_of(&node("b")), Some(MemberState::Alive));
    assert_eq!(engine.stats.ticks, 3);
}

#[test]
fn absent_peer_transitions_through_suspicion_to_dead_without_input() {
    let mut engine = make_engine("a", &[("b", 2)]);
    let mut io = Script::default();
    turn(&mut engine, &mut io, 0, true).unwrap();
    turn(&mut engine, &mut io, 20, true).unwrap();
    turn(&mut engine, &mut io, 100, true).unwrap();
    assert_eq!(engine.swim.state_of(&node("b")), Some(MemberState::Suspect));
    for now in (105..=2000).step_by(5) { turn(&mut engine, &mut io, now, true).unwrap(); }
    assert_eq!(engine.swim.state_of(&node("b")), Some(MemberState::Dead));
    let events = engine.swim.drain_events();
    assert_eq!(events.iter().map(|e| e.kind).collect::<Vec<_>>(), vec![MembershipKind::Suspect, MembershipKind::Dead]);
}

#[test]
fn actual_three_node_indirect_probe_relays_ack_when_direct_packet_is_lost() {
    let mut a = make_engine("a", &[("b", 2), ("c", 3)]);
    let mut first = Script::default();
    turn(&mut a, &mut first, 0, true).unwrap();
    let direct_target = first.sent[0].0;
    // Deliberately lose the direct probe; drive its actual timeout escalation.
    let mut indirect = Script::default();
    turn(&mut a, &mut indirect, 20, true).unwrap();
    assert_eq!(indirect.sent.len(), 1);
    let (helper_addr, ping_req) = indirect.sent.pop().unwrap();
    assert_ne!(helper_addr, direct_target);
    let (helper_name, target_name, target_port) = if helper_addr == address(2) { ("b", "c", 3) } else { ("c", "b", 2) };
    let mut helper = make_engine(helper_name, &[("a", 1), (target_name, target_port)]);
    let mut target = make_engine(target_name, &[("a", 1), (helper_name, helper_addr.port())]);
    helper.receive(20, address(1), &ping_req).unwrap();
    let mut helper_io = Script::default();
    turn(&mut helper, &mut helper_io, 20, false).unwrap();
    assert_eq!(helper_io.sent[0].0, direct_target);
    target.receive(21, helper_addr, &helper_io.sent[0].1).unwrap();
    let mut target_io = Script::default();
    turn(&mut target, &mut target_io, 21, false).unwrap();
    helper.receive(22, direct_target, &target_io.sent[0].1).unwrap();
    helper_io.sent.clear();
    turn(&mut helper, &mut helper_io, 22, false).unwrap();
    assert_eq!(helper_io.sent[0].0, address(1));
    a.receive(23, helper_addr, &helper_io.sent[0].1).unwrap();
    turn(&mut a, &mut Script::default(), 100, true).unwrap();
    assert_eq!(a.swim.state_of(&node(target_name)), Some(MemberState::Alive));
    assert!(!a.swim.drain_events().iter().any(|e| e.kind == MembershipKind::Suspect));
}

#[test]
fn malformed_foreign_oversized_and_unconfigured_gossip_do_not_touch_protocol() {
    let mut engine = make_engine("a", &[("b", 2)]);
    let ping = bytes(Packet::new(Payload::Ping { seq: 9 }));
    engine.receive(1, address(999), &ping).unwrap();
    engine.receive(1, address(2), &[0]).unwrap();
    engine.receive(1, address(2), &vec![0; 1401]).unwrap();
    let mut trailing = ping.clone(); trailing.push(0);
    engine.receive(1, address(2), &trailing).unwrap();
    for rumor in [Rumor::alive(node("outsider"), 0), Rumor::suspect(node("b"), 0, node("outsider"))] {
        engine.receive(1, address(2), &bytes(Packet { payload: Payload::Ping { seq: 9 }, gossip: vec![rumor] })).unwrap();
    }
    engine.receive(1, address(2), &bytes(Packet::new(Payload::PingReq { seq: 1, target: node("outsider") }))).unwrap();
    assert_eq!(engine.swim.member_count(), 1); // only the admitted peer; local is excluded
    assert_eq!(engine.swim.state_of(&node("b")), Some(MemberState::Alive));
    assert!(engine.outbox.is_empty());
    assert_eq!(engine.stats.unknown_sources, 1);
    assert_eq!(engine.stats.malformed_datagrams, 2);
    assert_eq!(engine.stats.oversized_datagrams, 1);
    assert_eq!(engine.stats.unauthorized_packets, 3);
    assert_eq!(engine.stats.accepted_packets, 0);
    // Causal positive control: a legitimate packet takes the real core path.
    engine.receive(2, address(2), &ping).unwrap();
    assert_eq!(engine.stats.accepted_packets, 1);
    assert_eq!(engine.outbox.len(), 1);
}

#[test]
fn outbox_overflow_is_explicit_and_never_exceeds_bound() {
    let mut engine = make_engine("a", &[("b", 2)]);
    engine.config.max_queued_datagrams = 1;
    let ping = bytes(Packet::new(Payload::Ping { seq: 4 }));
    engine.receive(0, address(2), &ping).unwrap();
    let retained = engine.outbox.front().unwrap().bytes.clone();
    assert!(matches!(engine.receive(1, address(2), &ping), Err(SwimDriverError::OutboxFull)));
    assert_eq!(engine.outbox.len(), 1);
    assert_eq!(engine.outbox.front().unwrap().bytes, retained);
    assert_eq!(engine.stats.queue_high_water, 1);
    assert_eq!(engine.stats.sent_datagrams, 0);
}

#[test]
fn bounded_receive_batch_still_ticks_under_foreign_packet_flood() {
    let mut engine = make_engine("a", &[("b", 2)]);
    let mut io = Script::default();
    for _ in 0..100 { io.inbound.push_back((address(99), vec![0])); }
    assert_eq!(turn(&mut engine, &mut io, 0, true).unwrap(), engine::Turn::Yield);
    assert_eq!(io.inbound.len(), 96);
    assert_eq!(engine.stats.received_datagrams, 4);
    assert_eq!(engine.stats.ticks, 1);
    assert_eq!(engine.stats.sent_datagrams, 1);
}

#[test]
fn expired_unsent_probe_is_loss_not_a_successful_send() {
    let mut engine = make_engine("a", &[("b", 2)]);
    let mut io = Script { blocked: true, ..Script::default() };
    turn(&mut engine, &mut io, 0, true).unwrap();
    turn(&mut engine, &mut io, 500, false).unwrap();
    assert!(engine.outbox.is_empty());
    assert_eq!(engine.stats.expired_datagrams, 1);
    assert_eq!(engine.stats.sent_datagrams, 0);
}

#[test]
fn graceful_leave_fans_out_and_stops_probes_with_finite_pending_deadline() {
    let mut engine = make_engine("a", &[("b", 2), ("c", 3)]);
    engine.begin_leave(100).unwrap();
    let mut io = Script { blocked: true, ..Script::default() };
    assert_eq!(turn(&mut engine, &mut io, 101, true).unwrap(), engine::Turn::Park);
    assert_eq!(engine.stats.ticks, 0);
    assert!(matches!(turn(&mut engine, &mut io, 150, true), Err(SwimDriverError::LeaveTimeout)));
    assert_eq!(engine.stats.sent_datagrams, 0);

    let mut engine = make_engine("a", &[("b", 2), ("c", 3)]);
    engine.begin_leave(100).unwrap();
    let mut io = Script::default();
    assert_eq!(turn(&mut engine, &mut io, 101, true).unwrap(), engine::Turn::Left);
    assert_eq!(io.sent.len(), 2);
    for (_, data) in io.sent {
        assert_eq!(decode_packet(&data).unwrap().gossip, vec![Rumor::leave(node("a"), 1)]);
    }
}

#[test]
fn send_failure_and_partial_udp_progress_do_not_manufacture_leave_success() {
    let mut engine = make_engine("a", &[("b", 2)]);
    let mut io = Script { send_error: true, ..Script::default() };
    turn(&mut engine, &mut io, 0, true).unwrap();
    assert_eq!(engine.stats.send_errors, 1);
    assert_eq!(engine.stats.sent_datagrams, 0);
    engine.begin_leave(1).unwrap();
    assert!(matches!(turn(&mut engine, &mut io, 1, false), Err(SwimDriverError::Io(_))));
    assert_eq!(engine.stats.sent_datagrams, 0);
    io.send_error = false; io.partial = true;
    assert!(matches!(turn(&mut engine, &mut io, 2, false), Err(SwimDriverError::PartialDatagram)));
    assert_eq!(engine.stats.sent_datagrams, 0);
}

#[test]
fn observer_bounds_history_exposes_lag_and_wakes_on_terminal_owner_drop() {
    let shared = Arc::new(ObservationState::new(2));
    let observer = SwimObserver { shared: Arc::clone(&shared) };
    for kind in [MembershipKind::Alive, MembershipKind::Suspect, MembershipKind::Dead] {
        shared.publish(vec![MembershipEvent { node: node("b"), kind, incarnation: 0 }], SwimDriverStatus::Running, SwimDriverStats::default()).unwrap();
    }
    let snapshot = observer.snapshot();
    assert_eq!(snapshot.membership.event_count(), 3);
    assert_eq!(snapshot.membership.compact_base(), 1);
    assert_eq!(snapshot.membership.events_since(1).len(), 2);
    assert_eq!(snapshot.membership.kind_of(&node("b")), Some(MembershipKind::Dead));
    let mut changed = std::pin::pin!(observer.changed(snapshot.revision));
    let mut task = Context::from_waker(Waker::noop());
    assert!(changed.as_mut().poll(&mut task).is_pending());
    shared.finish_if_active(SwimDriverStatus::Dropped, SwimDriverStats::default());
    assert!(matches!(changed.as_mut().poll(&mut task), Poll::Ready(SwimObservation { status: SwimDriverStatus::Dropped, .. })));
}

#[test]
fn raw_driver_and_owned_run_future_preserve_send_and_drop_retirement() {
    fn is_send<T: Send>() {}
    is_send::<UdpSwimDriver>();
    is_send::<SwimDriverReport>();
    is_send::<SwimObserver>();
    fn require_send<T: Send>(value: T) -> T { value }
    let native = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    native.set_nonblocking(true).unwrap();
    let transport = UdpMembershipTransport::new(crate::net::UdpSocket::from_std(native).unwrap());
    let driver = UdpSwimDriver::new_trusted_network(node("a"), protocol(), 7,
        BTreeMap::new(), transport, config()).unwrap();
    let observer = driver.observer();
    let cx = Cx::for_testing();
    drop(require_send(driver.run(&cx)));
    assert_eq!(observer.snapshot().status, SwimDriverStatus::Dropped);
}

#[test]
fn invalid_topology_and_timing_are_refused_before_socket_polling() {
    for case in 0..6 {
        let native = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        native.set_nonblocking(true).unwrap();
        let transport = UdpMembershipTransport::new(crate::net::UdpSocket::from_std(native).unwrap());
        let mut bounds = config();
        let mut peers = BTreeMap::from([(node("b"), address(2))]);
        match case {
            0 => bounds.io_batch = 0,
            1 => bounds.tick_ms = 21,
            2 => bounds.tick_ms = u64::MAX,
            3 => { peers.insert(node("c"), address(2)); }
            4 => { peers.insert(node("a"), address(3)); }
            _ => { peers.insert(node(&"x".repeat(256)), address(3)); }
        }
        assert!(matches!(UdpSwimDriver::new_trusted_network(node("a"), protocol(), 7,
            peers, transport, bounds), Err(SwimDriverError::Configuration(_))), "case {case}");
    }
}
