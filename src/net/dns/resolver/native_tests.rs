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
        let error = socket.recv_from(&mut bytes).unwrap_err();
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
