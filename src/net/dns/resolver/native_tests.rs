use super::*;
use crate::runtime::{Runtime, RuntimeBuilder};
use crate::types::{Budget, CancelReason, RegionId, TaskId};
use parking_lot::Mutex;
use std::net::{TcpListener, UdpSocket as PeerUdp};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::task::Waker;

fn runtime(workers: usize) -> Runtime {
    let builder = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread().worker_threads(workers)
    };
    builder.with_reactor(crate::runtime::reactor::create_reactor().unwrap()).build().unwrap()
}

/// The owned cancellation-Waker registrations on `cx`, by token.
///
/// `Runtime::block_on` registers its caller's cancellation wake on the root
/// context it drives for exactly the length of the drive (d2322f15a), so a
/// lookup that leaks nothing leaves that one entry on the polling root.
fn cancel_waker_tokens(cx: &Cx) -> Vec<u64> {
    let mut tokens: Vec<u64> = cx
        .inner
        .read()
        .cancel_waker_registrations
        .iter()
        .map(|registration| registration.token)
        .collect();
    tokens.sort_unstable();
    tokens
}

fn resolver(address: SocketAddr) -> Resolver {
    Resolver::with_config(ResolverConfig {
        nameservers: vec![address],
        timeout: Duration::from_secs(3),
        retries: 0,
        ..ResolverConfig::default()
    })
}

fn udp() -> PeerUdp {
    let socket = PeerUdp::bind("127.0.0.1:0").unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
    socket.set_write_timeout(Some(Duration::from_secs(4))).unwrap();
    socket
}

fn receive(socket: &PeerUdp) -> (Vec<u8>, SocketAddr) {
    let mut packet = [0u8; 1024];
    let (count, source) = socket.recv_from(&mut packet).unwrap();
    (packet[..count].to_vec(), source)
}

fn name_wire(name: &str) -> Vec<u8> {
    let mut wire = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        wire.push(u8::try_from(label.len()).unwrap());
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);
    wire
}

fn answer(query: &[u8], flags: u16, record: Option<(u16, u32, &[u8])>) -> Vec<u8> {
    let mut packet = query.to_vec();
    packet[2..4].copy_from_slice(&flags.to_be_bytes());
    let count = u16::from(record.is_some());
    packet[6..8].copy_from_slice(&count.to_be_bytes());
    if let Some((kind, ttl, data)) = record {
        packet.extend_from_slice(&[0xc0, 0x0c]);
        packet.extend_from_slice(&kind.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&ttl.to_be_bytes());
        packet.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
        packet.extend_from_slice(data);
    }
    packet
}

fn tcp_query(peer: &mut std::net::TcpStream) -> Vec<u8> {
    peer.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
    peer.set_write_timeout(Some(Duration::from_secs(4))).unwrap();
    let mut length = [0u8; 2];
    peer.read_exact(&mut length).unwrap();
    let mut packet = vec![0; usize::from(u16::from_be_bytes(length))];
    peer.read_exact(&mut packet).unwrap();
    packet
}

fn closed(peer: &mut std::net::TcpStream) {
    let mut byte = [0];
    match peer.read(&mut byte) {
        Ok(0) => {},
        Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {},
        result => panic!("DNS request retained its owned TCP socket: {result:?}"),
    }
}

#[test]
fn native_records_reject_unrelated_replies_and_share_positive_negative_ip_cache() {
    for workers in [1, 2] {
        let socket = udp();
        let address = socket.local_addr().unwrap();
        let queries = Arc::new(AtomicUsize::new(0));
        let counted = queries.clone();
        let peer = std::thread::spawn(move || {
            for _ in 0..7 {
                let (query, source) = receive(&socket);
                counted.fetch_add(1, Ordering::SeqCst);
                let (name, kind) = first_question(&query).unwrap();
                if name == "absent.example" {
                    socket.send_to(&answer(&query, 0x8183, None), source).unwrap();
                    continue;
                }
                let mut data = Vec::new();
                match kind {
                    1 => data.extend_from_slice(&[192, 0, 2, 42]),
                    28 => data.extend_from_slice(&Ipv6Addr::LOCALHOST.octets()),
                    15 => {
                        data.extend_from_slice(&10u16.to_be_bytes());
                        data.extend_from_slice(&name_wire("mail.example"));
                    }
                    33 => {
                        data.extend_from_slice(&[0, 1, 0, 2, 0x20, 0xfb]);
                        data.extend_from_slice(&name_wire("service.example"));
                    }
                    16 => data.extend_from_slice(b"\x05hello\x06 world"),
                    _ => panic!("unexpected query type {kind}"),
                }
                let response = answer(&query, 0x8180, Some((kind, 45, &data)));
                let mut wrong_id = response.clone();
                wrong_id[0] ^= 0x80;
                socket.send_to(&wrong_id, source).unwrap();
                let mut wrong_question = response.clone();
                wrong_question[13] ^= 1;
                socket.send_to(&wrong_question, source).unwrap();
                let mut wrong_class = response.clone();
                wrong_class[query.len() - 1] = 3;
                socket.send_to(&wrong_class, source).unwrap();
                socket.send_to(&response, source).unwrap();
            }
        });
        let runtime = runtime(workers);
        let resolver = resolver(address);
        let root = runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let driver_wake = cancel_waker_tokens(&cx);
            assert_eq!(driver_wake.len(), 1, "the drive registers only its caller wake");
            let found = resolver.lookup_ip_native(&cx, "dual.example").await.unwrap();
            assert_eq!(found.addresses(), &[IpAddr::V6(Ipv6Addr::LOCALHOST), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42))]);
            assert_eq!(found.ttl(), Duration::from_secs(45));
            let count = queries.load(Ordering::SeqCst);
            let hits = resolver.cache_stats().hits;
            assert_eq!(resolver.lookup_ip_native(&cx, "DUAL.example").await.unwrap().addresses(), found.addresses());
            assert_eq!(resolver.cache_stats().hits, hits + 1);
            assert_eq!(queries.load(Ordering::SeqCst), count);
            // Existing callers see the same cache entry without a blocking lookup.
            assert_eq!(resolver.lookup_ip("dual.example").await.unwrap().addresses(), found.addresses());

            let mx = resolver.lookup_mx_native(&cx, "mail.example").await.unwrap();
            let mx = mx.records().next().unwrap();
            assert_eq!((mx.preference, mx.exchange.as_str()), (10, "mail.example"));
            let srv = resolver.lookup_srv_native(&cx, "_service._tcp.example").await.unwrap();
            let srv = srv.records().next().unwrap();
            assert_eq!((srv.priority, srv.weight, srv.port, srv.target.as_str()), (1, 2, 8443, "service.example"));
            let txt = resolver.lookup_txt_native(&cx, "text.example").await.unwrap();
            assert_eq!(txt.records().collect::<Vec<_>>(), ["hello world"]);
            assert!(matches!(resolver.lookup_ip_native(&cx, "absent.example").await, Err(DnsError::NoRecords(_))));
            let count = queries.load(Ordering::SeqCst);
            let hits = resolver.cache_stats().hits;
            assert!(matches!(resolver.lookup_ip_native(&cx, "absent.example").await, Err(DnsError::NoRecords(_))));
            assert_eq!(queries.load(Ordering::SeqCst), count);
            assert_eq!(resolver.cache_stats().hits, hits + 1);
            assert_eq!(cancel_waker_tokens(&cx), driver_wake);
            cx
        });
        assert!(root.inner.read().cancel_waker_registrations.is_empty());
        peer.join().unwrap();
        assert_eq!(queries.load(Ordering::SeqCst), 7);
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }
}

#[test]
fn native_dns_tcp_fallback_reads_fragmented_length_and_payload_then_closes() {
    for workers in [1, 2] {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = tcp.local_addr().unwrap();
        let socket = PeerUdp::bind(address).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
        let peer = std::thread::spawn(move || {
            let (query, source) = receive(&socket);
            let mut truncated = answer(&query, 0x8380, None);
            // The TC answer declares a record but truncates its body. The
            // hardened parser must fall back before parsing missing RDATA.
            truncated[6..8].copy_from_slice(&1u16.to_be_bytes());
            socket.send_to(&truncated, source).unwrap();
            let (mut stream, _) = tcp.accept().unwrap();
            let repeated = tcp_query(&mut stream);
            assert_eq!(repeated, query, "TCP preserves the original query identity");
            let mut data = Vec::new();
            for _ in 0..4 {
                data.push(250);
                data.extend_from_slice(&[b'x'; 250]);
            }
            let response = answer(&query, 0x8180, Some((16, 60, &data)));
            let wire = [u16::try_from(response.len()).unwrap().to_be_bytes().as_slice(), &response].concat();
            for chunk in wire.chunks(3) {
                stream.write_all(chunk).unwrap();
            }
            closed(&mut stream);
        });
        let runtime = runtime(workers);
        let root = runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let driver_wake = cancel_waker_tokens(&cx);
            assert_eq!(driver_wake.len(), 1, "the drive registers only its caller wake");
            let result = resolver(address).lookup_txt_native(&cx, "large.example").await.unwrap();
            assert_eq!(result.records().collect::<Vec<_>>(), ["x".repeat(1000).as_str()]);
            assert_eq!(cancel_waker_tokens(&cx), driver_wake);
            cx
        });
        assert!(root.inner.read().cancel_waker_registrations.is_empty());
        peer.join().unwrap();
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }
}

#[test]
fn native_dns_parked_tcp_cancel_deadline_drop_and_authority_loss_retire_socket() {
    for workers in [1, 2] {
        for action in 0..4 {
            let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = tcp.local_addr().unwrap();
            let socket = PeerUdp::bind(address).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
            let received = Arc::new(AtomicBool::new(false));
            let waker: Arc<Mutex<Option<Waker>>> = Arc::new(Mutex::new(None));
            let ready = received.clone();
            let wake = waker.clone();
            let peer = std::thread::spawn(move || {
                let (query, source) = receive(&socket);
                socket.send_to(&answer(&query, 0x8380, None), source).unwrap();
                let (mut stream, _) = tcp.accept().unwrap();
                assert_eq!(tcp_query(&mut stream), query);
                ready.store(true, Ordering::Release);
                if let Some(waker) = wake.lock().as_ref() { waker.wake_by_ref(); }
                closed(&mut stream);
            });
            let runtime = runtime(workers);
            let native = runtime.request_cx_with_budget(Budget::INFINITE);
            let clock = Arc::new(crate::time::VirtualClock::starting_at(Time::from_secs(10)));
            let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
            let owner = Cx::new_with_drivers(
                RegionId::new_for_test(0, 1), TaskId::new_for_test(71, 0), Budget::INFINITE,
                None, native.io_driver_handle(), None, Some(timer.clone()), None,
            );
            let (parked_tx, parked_rx) = mpsc::channel();
            let controller = if action < 2 {
                let owner = owner.clone();
                Some(std::thread::spawn(move || {
                    parked_rx.recv_timeout(Duration::from_secs(4)).unwrap();
                    if action == 0 {
                        owner.cancel_with_reason(CancelReason::user("DNS consumer stopped"));
                    } else {
                        clock.advance(4_000_000_000);
                        let _ = timer.process_timers();
                    }
                }))
            } else { None };
            let root = runtime.block_on(async {
                let driver_wake = cancel_waker_tokens(&Cx::current().unwrap());
                assert_eq!(driver_wake.len(), 1, "the drive registers only its caller wake");
                let resolver = resolver(address);
                let mut lookup = Box::pin(resolver.lookup_txt_native(&owner, "parked.example"));
                let mut witnessed = false;
                let result = poll_fn(|task| {
                    *waker.lock() = Some(task.waker().clone());
                    let result = lookup.as_mut().poll(task);
                    if result.is_pending() && received.load(Ordering::Acquire) && !witnessed {
                        witnessed = true;
                        match action {
                            0 | 1 => parked_tx.send(()).unwrap(),
                            2 => return Poll::Ready(None),
                            _ => {
                                let _restriction = Cx::push_restriction(CapMask::none());
                                return lookup.as_mut().poll(task).map(Some);
                            }
                        }
                    }
                    result.map(Some)
                }).await;
                assert!(witnessed, "the lookup must park after the peer reads its TCP query");
                match (action, result) {
                    (0, Some(Err(DnsError::Cancelled))) | (1, Some(Err(DnsError::Timeout)))
                    | (2, None) | (3, Some(Err(DnsError::Io(_)))) => {},
                    (_, result) => panic!("incorrect terminal result for action {action}: {result:?}"),
                }
                drop(lookup);
                assert!(owner.inner.read().cancel_waker_registrations.is_empty());
                assert_eq!(cancel_waker_tokens(&Cx::current().unwrap()), driver_wake);
                assert!(Cx::current().unwrap().checkpoint().is_ok(), "cancelling DNS must not cancel its polling task");
                Cx::current().unwrap()
            });
            assert!(root.inner.read().cancel_waker_registrations.is_empty());
            if let Some(controller) = controller { controller.join().unwrap(); }
            peer.join().unwrap();
            assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
        }
    }
}

#[test]
fn native_dns_refuses_missing_owner_or_poller_authority_before_sending() {
    for workers in [1, 2] {
        let runtime = runtime(workers);
        let native = runtime.request_cx_with_budget(Budget::INFINITE);
        let restricted = {
            let _current = Cx::set_current(Some(native.clone()));
            let _restriction = Cx::push_restriction(CapMask::none());
            Cx::current().unwrap()
        };
        let socket = udp();
        socket.set_read_timeout(Some(Duration::from_millis(30))).unwrap();
        let resolver = resolver(socket.local_addr().unwrap());
        for (owner, poller) in [(restricted.clone(), native.clone()), (native.clone(), restricted)] {
            let _current = Cx::set_current(Some(poller));
            let mut future = Box::pin(resolver.lookup_ip_native(&owner, "denied.example"));
            let mut task = Context::from_waker(Waker::noop());
            assert!(matches!(future.as_mut().poll(&mut task), Poll::Ready(Err(DnsError::Io(_)))));
            drop(future);
            assert!(owner.inner.read().cancel_waker_registrations.is_empty());
        }
        let mut bytes = [0; 1024];
        // A receive with a read timeout returns EINTR rather than restarting, so only a
        // datagram or the timeout may end this wait.
        let error = loop {
            match socket.recv_from(&mut bytes) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                other => break other.unwrap_err(),
            }
        };
        assert!(matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut));
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }
}

#[test]
fn native_dns_partial_family_failure_never_poison_caches_and_retries_failed_servers_only() {
    for workers in [1, 2] {
        let socket = udp();
        let address = socket.local_addr().unwrap();
        let queries = Arc::new(AtomicUsize::new(0));
        let count = queries.clone();
        let peer = std::thread::spawn(move || {
            // Both repeated public lookups must actually query the peer:
            // SERVFAIL in the AAAA half makes each successful A result TTL0.
            for _ in 0..6 {
                let (query, source) = receive(&socket);
                count.fetch_add(1, Ordering::SeqCst);
                let (_, kind) = first_question(&query).unwrap();
                let response = if kind == 1 {
                    answer(&query, 0x8180, Some((1, 60, &[192, 0, 2, 7])))
                } else {
                    answer(&query, 0x8182, None)
                };
                socket.send_to(&response, source).unwrap();
            }
        });
        let runtime = runtime(workers);
        let resolver = Resolver::with_config(ResolverConfig { retries: 1, ..resolver(address).config });
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            for _ in 0..2 {
                let result = resolver.lookup_ip_native(&cx, "partial.example").await.unwrap();
                assert_eq!(result.addresses(), &[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))]);
                assert_eq!(result.ttl(), Duration::ZERO);
            }
            assert_eq!(resolver.cache_stats().hits, 0);
        });
        peer.join().unwrap();
        assert_eq!(queries.load(Ordering::SeqCst), 6);
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }
}

#[test]
fn native_dns_bounds_unrelated_response_work_and_preserves_system_opt_in() {
    for workers in [1, 2] {
        let socket = udp();
        let address = socket.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            let (query, source) = receive(&socket);
            let mut wrong = answer(&query, 0x8180, Some((16, 60, b"\x01x")));
            wrong[0] ^= 0x80;
            for _ in 0..MAX_UNRELATED_REPLIES {
                socket.send_to(&wrong, source).unwrap();
            }
        });
        let runtime = runtime(workers);
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            assert!(matches!(Resolver::new().lookup_txt_native(&cx, "no-system-fallback.example").await, Err(DnsError::Io(message)) if message.contains("explicit")));
            assert!(matches!(resolver(address).lookup_txt_native(&cx, "mismatch.example").await, Err(DnsError::Protocol(message)) if message.contains("unrelated")));
            let literal = Resolver::new().lookup_ip_native(&cx, "[::1]").await.unwrap();
            assert_eq!(literal.addresses(), &[IpAddr::V6(Ipv6Addr::LOCALHOST)]);
            assert!(matches!(Resolver::new().lookup_ip_native(&cx, "private.invalid").await, Err(DnsError::NoRecords(_))));
        });
        peer.join().unwrap();
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }
}

#[test]
fn native_dns_budget_meet_keeps_its_owner_clock_across_foreign_pollers() {
    let runtime = runtime(1);
    let native = runtime.request_cx_with_budget(Budget::INFINITE);
    for (owner_origin, poller_origin) in [(1_000_000, 10), (10, 1_000_000)] {
        let owner_clock = Arc::new(crate::time::VirtualClock::starting_at(Time::from_nanos(owner_origin)));
        let owner = Cx::new_with_drivers(
            RegionId::new_for_test(0, 1), TaskId::new_for_test(72, 0),
            Budget::INFINITE.with_deadline(Time::from_nanos(owner_origin + 100)),
            None, native.io_driver_handle(), None,
            Some(TimerDriverHandle::with_virtual_clock(owner_clock.clone())), None,
        );
        let foreign_clock = Arc::new(crate::time::VirtualClock::starting_at(Time::from_nanos(poller_origin)));
        let foreign_timer = TimerDriverHandle::with_virtual_clock(foreign_clock);
        let foreign = Cx::new_with_drivers(
            RegionId::new_for_test(0, 1), TaskId::new_for_test(73, 0),
            Budget::INFINITE.with_deadline(Time::from_nanos(poller_origin + 7)),
            None, native.io_driver_handle(), None, Some(foreign_timer.clone()), None,
        );
        let mut operation = {
            let _current = Cx::set_current(Some(owner.clone()));
            NativeOwner::new(&owner, Duration::from_nanos(500))
        };
        let _current = Cx::set_current(Some(foreign.clone()));
        let mut task = Context::from_waker(Waker::noop());
        operation.check(&mut task).unwrap();
        assert_eq!(operation.deadline.at, Time::from_nanos(owner_origin + 7));
        owner_clock.advance(6);
        operation.check(&mut task).unwrap();
        owner_clock.advance(1);
        assert!(matches!(operation.check(&mut task), Err(DnsError::Timeout)));
        assert_eq!(foreign_timer.process_timers(), 0);
        drop(operation);
        assert!(owner.inner.read().cancel_waker_registrations.is_empty());
        assert!(foreign.inner.read().cancel_waker_registrations.is_empty());
    }
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

/// A current-thread runtime whose blocking pool forbids blocking work, with a native reactor.
fn forbidding_runtime() -> Runtime {
    RuntimeBuilder::current_thread()
        .with_reactor(crate::runtime::reactor::create_reactor().unwrap())
        .blocking_threads(0, 1)
        .blocking_admission_policy(crate::runtime::BlockingAdmissionPolicy::Forbidden)
        .build()
        .unwrap()
}

type Seen = Arc<Mutex<Vec<(String, u16)>>>;

/// A UDP DNS peer on a thread. Every datagram is recorded as `(name, type)` before `reply` decides the answer (`None`
/// stays silent), so a wrong question is visible to the test. The port stays open while it is silent, so no ICMP refusal
/// can reach the client and turn a timeout into an I/O error.
struct Peer {
    address: SocketAddr,
    seen: Seen,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Peer {
    fn serve(reply: impl Fn(&[u8], &str, u16) -> Option<Vec<u8>> + Send + 'static) -> Self {
        let socket = udp();
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let address = socket.local_addr().unwrap();
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (record, halt) = (seen.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            let mut bytes = [0u8; 1024];
            while !halt.load(Ordering::Acquire) {
                // A read timeout is an error: check the stop flag and read again.
                let Ok((count, source)) = socket.recv_from(&mut bytes) else {
                    continue;
                };
                let query = &bytes[..count];
                let (name, kind) = first_question(query).unwrap();
                record.lock().push((name.clone(), kind));
                if let Some(response) = reply(query, &name, kind) {
                    socket.send_to(&response, source).unwrap();
                }
            }
        });
        Self {
            address,
            seen,
            stop,
            thread: Some(thread),
        }
    }

    /// The questions received so far, sorted.
    fn seen(&self) -> Vec<(String, u16)> {
        let mut seen = self.seen.lock().clone();
        seen.sort();
        seen
    }

    fn finish(mut self) {
        self.stop.store(true, Ordering::Release);
        self.thread.take().unwrap().join().unwrap();
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

/// One A, one AAAA, one MX, one SRV and one TXT record for whatever name is asked.
fn standard_reply(query: &[u8], _name: &str, kind: u16) -> Option<Vec<u8>> {
    let mut data = Vec::new();
    Some(match kind {
        1 => answer(query, 0x8180, Some((1, 45, &[192, 0, 2, 7]))),
        28 => answer(
            query,
            0x8180,
            Some((
                28,
                45,
                &Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7).octets(),
            )),
        ),
        15 => {
            data.extend_from_slice(&10u16.to_be_bytes());
            data.extend_from_slice(&name_wire("mail.example"));
            answer(query, 0x8180, Some((15, 45, &data)))
        }
        33 => {
            data.extend_from_slice(&[0, 1, 0, 2, 0x20, 0xfb]);
            data.extend_from_slice(&name_wire("service.example"));
            answer(query, 0x8180, Some((33, 45, &data)))
        }
        16 => answer(query, 0x8180, Some((16, 45, b"\x05hello"))),
        _ => return None,
    })
}

fn v6() -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7))
}

fn v4() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))
}

/// After a forbidden-pool run: no blocking thread was started and no blocking work was queued.
fn assert_pool_idle(runtime: &Runtime) {
    let pool = runtime
        .blocking_handle()
        .expect("a pool that refuses, not an absent one");
    assert_eq!((pool.active_threads(), pool.pending_count()), (0, 0));
}

/// Under a forbidden blocking pool a resolver with explicit nameservers resolves `lookup_ip` on the reactor. Success is
/// itself the proof that the blocking path was not used (it refuses before scheduling anything under this policy). The
/// peer must have seen exactly the A and AAAA questions for the name asked, one lookup counts one cache miss, and the
/// repeat is one cache hit that sends nothing.
#[test]
fn forbidden_pool_lookup_ip_resolves_both_families_on_the_reactor_with_one_miss_then_one_hit() {
    let peer = Peer::serve(standard_reply);
    let runtime = forbidding_runtime();
    let resolver = resolver(peer.address);
    runtime.block_on(async {
        assert!(
            crate::runtime::spawn_blocking::current_pool_forbids_blocking(),
            "the context under test must forbid blocking work"
        );
        let first = resolver.lookup_ip("provider.example").await.unwrap();
        assert_eq!(first.addresses(), &[v6(), v4()]);
        let stats = resolver.cache_stats();
        assert_eq!(
            (stats.hits, stats.misses),
            (0, 1),
            "one uncached lookup is one miss"
        );
        let sent = peer.seen().len();
        let second = resolver.lookup_ip("provider.example").await.unwrap();
        assert_eq!(second.addresses(), first.addresses());
        let stats = resolver.cache_stats();
        assert_eq!((stats.hits, stats.misses), (1, 1), "the repeat is one hit");
        assert_eq!(peer.seen().len(), sent, "a cached lookup sends no datagram");
    });
    assert_eq!(
        peer.seen(),
        [
            ("provider.example".to_owned(), 1),
            ("provider.example".to_owned(), 28)
        ]
    );
    assert_pool_idle(&runtime);
    peer.finish();
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

/// A name with only an AAAA record: the A family answers with no data, which is not a failure, so the AAAA address
/// is returned with its own TTL.
#[test]
fn forbidden_pool_lookup_ip_serves_an_aaaa_only_name() {
    let peer = Peer::serve(|query, _name, kind| match kind {
        1 => Some(answer(query, 0x8180, None)),
        _ => standard_reply(query, "", kind),
    });
    let runtime = forbidding_runtime();
    let resolver = resolver(peer.address);
    runtime.block_on(async {
        let found = resolver.lookup_ip("v6only.example").await.unwrap();
        assert_eq!(found.addresses(), &[v6()]);
        assert_eq!(found.ttl(), Duration::from_secs(45));
    });
    assert_eq!(
        peer.seen(),
        [
            ("v6only.example".to_owned(), 1),
            ("v6only.example".to_owned(), 28)
        ]
    );
    assert_pool_idle(&runtime);
    peer.finish();
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

/// Each record lookup sends exactly one question of its own type for the name asked, and nothing else.
#[test]
fn forbidden_pool_lookup_mx_sends_one_mx_question_and_parses_the_answer() {
    let peer = Peer::serve(standard_reply);
    let runtime = forbidding_runtime();
    let resolver = resolver(peer.address);
    runtime.block_on(async {
        let mx = resolver.lookup_mx("zone.example").await.unwrap();
        let mx = mx.records().next().unwrap();
        assert_eq!((mx.preference, mx.exchange.as_str()), (10, "mail.example"));
    });
    assert_eq!(peer.seen(), [("zone.example".to_owned(), 15)]);
    assert_pool_idle(&runtime);
    peer.finish();
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

#[test]
fn forbidden_pool_lookup_srv_sends_one_srv_question_and_parses_the_answer() {
    let peer = Peer::serve(standard_reply);
    let runtime = forbidding_runtime();
    let resolver = resolver(peer.address);
    runtime.block_on(async {
        let srv = resolver.lookup_srv("_sip._tcp.zone.example").await.unwrap();
        let srv = srv.records().next().unwrap();
        assert_eq!(
            (srv.priority, srv.weight, srv.port, srv.target.as_str()),
            (1, 2, 8443, "service.example")
        );
    });
    assert_eq!(peer.seen(), [("_sip._tcp.zone.example".to_owned(), 33)]);
    assert_pool_idle(&runtime);
    peer.finish();
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

#[test]
fn forbidden_pool_lookup_txt_sends_one_txt_question_and_parses_the_answer() {
    let peer = Peer::serve(standard_reply);
    let runtime = forbidding_runtime();
    let resolver = resolver(peer.address);
    runtime.block_on(async {
        let txt = resolver.lookup_txt("zone.example").await.unwrap();
        assert_eq!(txt.records().collect::<Vec<_>>(), ["hello"]);
    });
    assert_eq!(peer.seen(), [("zone.example".to_owned(), 16)]);
    assert_pool_idle(&runtime);
    peer.finish();
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

/// A truncated UDP answer falls back to TCP through the public lookup, on the reactor, under a forbidden pool.
#[test]
fn forbidden_pool_txt_lookup_falls_back_to_tcp_on_truncation() {
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = tcp.local_addr().unwrap();
    let socket = PeerUdp::bind(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(4)))
        .unwrap();
    let peer = std::thread::spawn(move || {
        let (query, source) = receive(&socket);
        socket
            .send_to(&answer(&query, 0x8380, None), source)
            .unwrap();
        let (mut stream, _) = tcp.accept().unwrap();
        assert_eq!(tcp_query(&mut stream), query, "TCP repeats the same query");
        let response = answer(&query, 0x8180, Some((16, 60, b"\x05hello")));
        let wire = [
            u16::try_from(response.len())
                .unwrap()
                .to_be_bytes()
                .as_slice(),
            &response,
        ]
        .concat();
        stream.write_all(&wire).unwrap();
        closed(&mut stream);
        first_question(&query).unwrap()
    });
    let runtime = forbidding_runtime();
    let resolver = resolver(address);
    runtime.block_on(async {
        let txt = resolver.lookup_txt("large.example").await.unwrap();
        assert_eq!(txt.records().collect::<Vec<_>>(), ["hello"]);
    });
    assert_eq!(peer.join().unwrap(), ("large.example".to_owned(), 16));
    assert_pool_idle(&runtime);
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

/// Timeout, cancellation and drop of a lookup on the reactor under a forbidden pool each end with the right result,
/// retire the owner's cancellation registration, leave the pool untouched and do not cancel the polling task. The policy
/// is asserted inside the owner's scope, so the test cannot pass on an open-pool path.
#[test]
fn forbidden_pool_dns_timeout_cancel_and_drop_end_cleanly() {
    for action in 0..3 {
        // The peer reads the query and never answers.
        let peer = Peer::serve(|_, _, _| None);
        let runtime = forbidding_runtime();
        let owner = runtime.request_cx_with_budget(Budget::INFINITE);
        let resolver = Resolver::with_config(ResolverConfig {
            nameservers: vec![peer.address],
            cache_enabled: false,
            retries: 0,
            timeout: Duration::from_millis(if action == 0 { 250 } else { 3000 }),
            ..ResolverConfig::default()
        });
        let started = Instant::now();
        let root = runtime.block_on(async {
            let mut lookup = Box::pin(resolver.lookup_ip("parked.example"));
            let mut witnessed = false;
            let result = poll_fn(|task| {
                // The lookup's owner is the calling context, so each poll runs under the explicit owner.
                let _current = Cx::set_current(Some(owner.clone()));
                assert!(
                    crate::runtime::spawn_blocking::current_pool_forbids_blocking(),
                    "the owner's scope must forbid blocking work"
                );
                let polled = lookup.as_mut().poll(task);
                if polled.is_pending() && !witnessed {
                    if peer.seen().is_empty() {
                        // Keep polling until the query is on the wire.
                        task.waker().wake_by_ref();
                    } else {
                        witnessed = true;
                        match action {
                            1 => {
                                owner
                                    .cancel_with_reason(CancelReason::user("DNS consumer stopped"));
                            }
                            2 => return Poll::Ready(None),
                            _ => {}
                        }
                    }
                }
                polled.map(Some)
            })
            .await;
            match (action, result) {
                (0, Some(Err(DnsError::Timeout)))
                | (1, Some(Err(DnsError::Cancelled)))
                | (2, None) => {}
                (_, result) => panic!("incorrect terminal result for action {action}: {result:?}"),
            }
            drop(lookup);
            assert!(owner.inner.read().cancel_waker_registrations.is_empty());
            assert!(
                Cx::current().unwrap().checkpoint().is_ok(),
                "DNS must not cancel its polling task"
            );
            Cx::current().unwrap()
        });
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the lookup ended promptly"
        );
        assert!(root.inner.read().cancel_waker_registrations.is_empty());
        assert_pool_idle(&runtime);
        peer.finish();
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }
}

/// The native deadline meets the owner's `Budget` deadline, so a budget that ends before the resolver timeout wins.
#[test]
fn forbidden_pool_dns_budget_deadline_wins_over_a_longer_resolver_timeout() {
    let peer = Peer::serve(|_, _, _| None);
    let runtime = forbidding_runtime();
    let probe = runtime.request_cx_with_budget(Budget::INFINITE);
    let now = probe.timer_driver().unwrap().now();
    let owner = runtime
        .request_cx_with_budget(Budget::INFINITE.with_deadline(now + Duration::from_millis(150)));
    let resolver = Resolver::with_config(ResolverConfig {
        nameservers: vec![peer.address],
        cache_enabled: false,
        retries: 0,
        timeout: Duration::from_secs(3),
        ..ResolverConfig::default()
    });
    let started = Instant::now();
    let result = runtime.block_on(async {
        let _current = Cx::set_current(Some(owner.clone()));
        assert!(crate::runtime::spawn_blocking::current_pool_forbids_blocking());
        resolver.lookup_ip("budget.example").await
    });
    assert!(matches!(result, Err(DnsError::Timeout)), "{result:?}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the 150 ms budget, not the 3 s resolver timeout, ended the lookup"
    );
    assert_pool_idle(&runtime);
    peer.finish();
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

/// Implicit native routing needs the owner to retain BOTH a native I/O driver and a timer driver, and to permit both.
/// A context with I/O but no TIME would make the native deadline start the process-global fallback timer thread, so it
/// is refused like every other forbidden context, with the shared message and not one datagram sent. The same lookup
/// with I/O and TIME resolves. Controls: an open pool and code outside any context keep the legacy path and resolve.
#[test]
fn forbidden_pool_native_routing_needs_io_and_time_and_otherwise_refuses_with_zero_queries() {
    type IoOnly = crate::cx::cap::CapSet<false, false, false, true, false>;
    type TimeOnly = crate::cx::cap::CapSet<false, true, false, false, false>;
    type IoAndTime = crate::cx::cap::CapSet<false, true, false, true, false>;
    let peer = Peer::serve(standard_reply);
    let resolver = Resolver::with_config(ResolverConfig {
        nameservers: vec![peer.address],
        cache_enabled: false,
        retries: 0,
        timeout: Duration::from_secs(2),
        ..ResolverConfig::default()
    });
    let message = crate::runtime::spawn_blocking::forbidden_io_error().to_string();
    let refused = |result: &Result<LookupIp, DnsError>| matches!(result, Err(DnsError::Io(found)) if *found == message);
    let forbidden = crate::runtime::BlockingPool::with_config_and_policies(
        0,
        1,
        crate::runtime::blocking_pool::BlockingPoolOptions::default(),
        crate::runtime::BlockingQueuePolicy::Fifo,
        crate::runtime::BlockingAdmissionPolicy::Forbidden,
    );
    let runtime = forbidding_runtime();
    let owner = runtime.request_cx_with_budget(Budget::INFINITE);
    runtime.block_on(async {
        {
            // I/O without TIME: the accidental thread fallback.
            let restricted = owner.restrict::<IoOnly>();
            let _current = restricted.set_current_restricted();
            assert!(crate::runtime::spawn_blocking::current_pool_forbids_blocking());
            assert!(refused(&resolver.lookup_ip("gate.example").await));
            assert!(matches!(
                resolver.lookup_mx("gate.example").await,
                Err(DnsError::Io(found)) if found == message
            ));
        }
        {
            // TIME without I/O: the existing I/O capability gate of the blocking path refuses it, before the pool does.
            let restricted = owner.restrict::<TimeOnly>();
            let _current = restricted.set_current_restricted();
            let result = resolver.lookup_ip("gate.example").await;
            assert!(matches!(result, Err(DnsError::Io(_))), "{result:?}");
        }
        {
            // No driver at all (a test context): the pool is forbidden, the reactor is unavailable.
            let driverless = Cx::for_testing().with_blocking_pool_handle(Some(forbidden.handle()));
            let _current = Cx::set_current(Some(driverless));
            assert!(refused(&resolver.lookup_ip("gate.example").await));
        }
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            peer.seen().is_empty(),
            "a refused lookup must not send a datagram"
        );

        // Paired positive: exactly I/O and TIME is enough.
        let restricted = owner.restrict::<IoAndTime>();
        let _current = restricted.set_current_restricted();
        let found = resolver.lookup_ip("gate.example").await.unwrap();
        assert_eq!(found.addresses(), &[v6(), v4()]);
    });
    assert_eq!(
        peer.seen(),
        [
            ("gate.example".to_owned(), 1),
            ("gate.example".to_owned(), 28)
        ]
    );
    assert_pool_idle(&runtime);
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    forbidden.shutdown();

    // Controls: an open pool and no context at all still take the blocking path and resolve.
    let sorted = |lookup: &LookupIp| {
        let mut addresses = lookup.addresses().to_vec();
        addresses.sort();
        addresses
    };
    let open = runtime_with_default_policy();
    let legacy = open.block_on(async { resolver.lookup_ip("control.example").await.unwrap() });
    assert_eq!(sorted(&legacy), [v4(), v6()]);
    assert!(open.shutdown_timeout(Duration::from_secs(3)));
    let outside = futures_lite::future::block_on(resolver.lookup_ip("control.example")).unwrap();
    assert_eq!(sorted(&outside), [v4(), v6()]);
    peer.finish();
}

/// A current-thread runtime with the default (permitted) blocking policy and a native reactor.
fn runtime_with_default_policy() -> Runtime {
    RuntimeBuilder::current_thread()
        .with_reactor(crate::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap()
}

/// Reading the system resolver configuration is blocking file I/O, so a forbidden pool must not trigger it even where
/// the reactor is available. The configuration reader is a counting trap. A resolver with explicit nameservers
/// resolves `lookup_ip`, `lookup_mx`, `lookup_srv` and `lookup_txt` on the reactor without calling it. A resolver with
/// none cannot use the reactor path and is refused with the shared message before the trap is called, and before any
/// datagram. Control: the same resolver on an open pool does call the trap, once, so the trap is live.
#[test]
fn forbidden_pool_never_reads_the_system_config_with_or_without_the_reactor() {
    static READS: AtomicUsize = AtomicUsize::new(0);
    static NAMESERVER: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();
    fn trap_reader() -> Vec<SocketAddr> {
        READS.fetch_add(1, Ordering::SeqCst);
        NAMESERVER.get().copied().into_iter().collect()
    }
    let peer = Peer::serve(standard_reply);
    NAMESERVER.set(peer.address).unwrap();
    let config = ResolverConfig {
        cache_enabled: false,
        retries: 0,
        timeout: Duration::from_secs(2),
        ..ResolverConfig::default()
    };
    let explicit = Resolver::with_config(ResolverConfig {
        nameservers: vec![peer.address],
        ..config.clone()
    })
    .with_system_config_reader(trap_reader);
    let unconfigured = Resolver::with_config(config).with_system_config_reader(trap_reader);
    let message = crate::runtime::spawn_blocking::forbidden_io_error().to_string();
    let runtime = forbidding_runtime();
    runtime.block_on(async {
        assert!(crate::runtime::spawn_blocking::current_pool_forbids_blocking());
        // No explicit nameservers: refused on a context that does have the reactor.
        assert!(matches!(
            unconfigured.lookup_mx("trap.example").await,
            Err(DnsError::Io(found)) if found == message
        ));
        assert!(matches!(
            unconfigured.lookup_srv("_sip._tcp.trap.example").await,
            Err(DnsError::Io(found)) if found == message
        ));
        assert!(matches!(
            unconfigured.lookup_txt("trap.example").await,
            Err(DnsError::Io(found)) if found == message
        ));
        assert_eq!(READS.load(Ordering::SeqCst), 0, "a refusal reads nothing");
        assert!(peer.seen().is_empty(), "a refusal sends no datagram");

        // Explicit nameservers: resolved on the reactor, and the configuration is still not read.
        let found = explicit.lookup_ip("trap.example").await.unwrap();
        assert_eq!(found.addresses(), &[v6(), v4()]);
        let mx = explicit.lookup_mx("trap.example").await.unwrap();
        assert_eq!(mx.records().count(), 1);
        let srv = explicit.lookup_srv("_sip._tcp.trap.example").await.unwrap();
        assert_eq!(srv.records().count(), 1);
        let txt = explicit.lookup_txt("trap.example").await.unwrap();
        assert_eq!(txt.records().collect::<Vec<_>>(), ["hello"]);
        assert_eq!(
            READS.load(Ordering::SeqCst),
            0,
            "explicit nameservers never read it"
        );
    });
    // `Peer::seen` is sorted by (name, type), so the expected multiset is normalized the same way: exactly these
    // five questions, each once (a missing, extra or duplicated question still fails).
    let mut expected: [(String, u16); 5] = [
        ("trap.example".to_owned(), 1),
        ("trap.example".to_owned(), 28),
        ("trap.example".to_owned(), 15),
        ("_sip._tcp.trap.example".to_owned(), 33),
        ("trap.example".to_owned(), 16),
    ];
    expected.sort();
    assert_eq!(peer.seen(), expected);
    assert_pool_idle(&runtime);
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));

    // Control: an open pool reads the configuration for the same resolver, once, and resolves through it.
    let open = runtime_with_default_policy();
    let legacy = open.block_on(async { unconfigured.lookup_txt("control.example").await.unwrap() });
    assert_eq!(legacy.records().collect::<Vec<_>>(), ["hello"]);
    assert_eq!(
        READS.load(Ordering::SeqCst),
        1,
        "the open pool still reads it"
    );
    assert!(open.shutdown_timeout(Duration::from_secs(3)));
    peer.finish();
}

/// The connection the listener has queued, within two seconds (it is already queued once the client's connect completed).
fn accept_within(listener: &TcpListener) -> (std::net::TcpStream, SocketAddr) {
    for _ in 0..200 {
        match listener.accept() {
            Ok(accepted) => return accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("accept failed: {error}"),
        }
    }
    panic!("the listener received no connection");
}

/// The whole user flow under a forbidden blocking pool: a NAME is resolved with explicit nameservers on the reactor and the
/// connection is then made to the resolved address on the reactor, so the pool sees no work at all. Both connect strategies
/// (Happy Eyeballs and sequential) are run. The peer must have seen exactly the A and AAAA questions for each name, and the
/// listener must have received the connection that the returned stream made.
#[test]
fn forbidden_pool_connect_by_name_resolves_then_connects_with_no_blocking_work() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let peer = Peer::serve(|query, _name, kind| match kind {
        1 => Some(answer(query, 0x8180, Some((1, 45, &[127, 0, 0, 1])))),
        28 => Some(answer(query, 0x8180, None)),
        _ => None,
    });
    let runtime = forbidding_runtime();
    for (happy_eyeballs, name) in [(true, "race.example"), (false, "sequential.example")] {
        let resolver = Resolver::with_config(ResolverConfig {
            nameservers: vec![peer.address],
            timeout: Duration::from_secs(3),
            retries: 0,
            happy_eyeballs,
            ..ResolverConfig::default()
        });
        let stream = runtime.block_on(async {
            assert!(crate::runtime::spawn_blocking::current_pool_forbids_blocking());
            resolver.happy_eyeballs_connect(name, port).await.unwrap()
        });
        assert_eq!(stream.peer_addr().unwrap(), loopback);
        let (_accepted, from) = accept_within(&listener);
        assert_eq!(from, stream.local_addr().unwrap());
    }
    assert_eq!(
        peer.seen(),
        [
            ("race.example".to_owned(), 1),
            ("race.example".to_owned(), 28),
            ("sequential.example".to_owned(), 1),
            ("sequential.example".to_owned(), 28)
        ]
    );
    assert_pool_idle(&runtime);
    peer.finish();
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}

/// Paired refusal for the flow above: with no explicit nameservers there is nothing to resolve a name with on the reactor, so
/// the same call is refused with the shared message before any connection is attempted, and the pool stays idle.
#[test]
fn forbidden_pool_connect_by_name_without_nameservers_is_refused_and_connects_to_nothing() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let unconfigured = Resolver::with_config(ResolverConfig {
        timeout: Duration::from_secs(2),
        retries: 0,
        ..ResolverConfig::default()
    });
    let message = crate::runtime::spawn_blocking::forbidden_io_error().to_string();
    let runtime = forbidding_runtime();
    runtime.block_on(async {
        let result = unconfigured
            .happy_eyeballs_connect("svc.example", port)
            .await;
        assert!(matches!(&result, Err(DnsError::Io(found)) if *found == message));
    });
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    assert_pool_idle(&runtime);
    assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
}
