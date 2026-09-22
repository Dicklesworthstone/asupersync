//! Native registered health RPC journeys; no simulated client channel.
//! br-asupersync-server-stack-hardening-eeexl1.10; fixed protobuf/H2 fixtures.

use super::*;
use crate::grpc::server::{Server, ServerStreamingConfig};
use crate::http::h1::server::HostPolicy;
use crate::http::h2::HpackDecoder;
use crate::runtime::RuntimeBuilder;
use crate::server::shutdown::ShutdownSignal;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::num::NonZeroUsize;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::time::Duration;

#[derive(Debug, PartialEq, Eq)]
enum WatchEvent {
    Parked(usize),
    Retired(usize),
}

// Witness the real health source returning Pending; a first response alone is
// not proof that cancellation reached a parked source. No behavior is mocked.
struct WitnessService {
    rpc: HealthRpcService,
    events: SyncSender<WatchEvent>,
    next: AtomicUsize,
}

impl NamedService for WitnessService {
    const NAME: &'static str = HealthRpcService::NAME;
}

impl ServiceHandler for WitnessService {
    fn descriptor(&self) -> &ServiceDescriptor { self.rpc.descriptor() }
    fn method_names(&self) -> Vec<&str> { self.rpc.method_names() }

    fn call_unary<'a>(
        &'a self, cx: &'a Cx, path: &'a str, request: Request<Bytes>, trailers: Metadata,
    ) -> ServiceHandlerFuture<'a> {
        self.rpc.call_unary(cx, path, request, trailers)
    }

    fn call_server_streaming<'a>(
        &'a self, cx: &'a Cx, path: &'a str, request: Request<Bytes>, trailers: Metadata,
    ) -> ServiceStreamingFuture<'a> {
        Box::pin(async move {
            let (source, trailers) = self.rpc.call_server_streaming(cx, path, request, trailers)
                .await?.into_parts();
            Ok(RegisteredServerStream::new(WitnessStream {
                source: Some(source),
                events: self.events.clone(),
                id: self.next.fetch_add(1, Ordering::SeqCst),
                parked: false,
            }).with_trailers(trailers))
        })
    }
}

struct WitnessStream {
    source: Option<ByteStream>,
    events: SyncSender<WatchEvent>,
    id: usize,
    parked: bool,
}

impl Streaming for WitnessStream {
    type Message = Bytes;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Bytes, Status>>> {
        let this = self.get_mut();
        let result = this.source.as_mut().expect("live health source").as_mut().poll_next(cx);
        if result.is_pending() && !this.parked {
            this.events.try_send(WatchEvent::Parked(this.id)).expect("bounded parked witness");
        }
        this.parked = result.is_pending();
        result
    }
}

impl Drop for WitnessStream {
    fn drop(&mut self) {
        // Drop the real source (including its waiter AND quota) before receipt.
        drop(self.source.take());
        let _ = self.events.try_send(WatchEvent::Retired(self.id));
    }
}

struct StopOnDrop(ShutdownSignal);
impl Drop for StopOnDrop {
    fn drop(&mut self) { self.0.trigger_immediate(); }
}

#[derive(Default)]
struct Reply {
    data: Vec<u8>,
    status: Option<String>,
    ended: bool,
    reset: Option<u32>,
}

struct Peer {
    socket: TcpStream,
    decoder: HpackDecoder,
    replies: BTreeMap<u32, Reply>,
    latest_stream: u32,
}

impl Peer {
    fn connect(address: SocketAddr, window: u32) -> Self {
        let socket = TcpStream::connect_timeout(&address, Duration::from_secs(3)).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut peer = Self {
            socket,
            decoder: HpackDecoder::new(),
            replies: BTreeMap::new(),
            latest_stream: 0,
        };
        peer.socket.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
        let mut settings = vec![0, 4];
        settings.extend_from_slice(&window.to_be_bytes());
        peer.send(4, 0, 0, &settings);
        peer
    }

    fn send(&mut self, kind: u8, flags: u8, id: u32, payload: &[u8]) {
        let length = u32::try_from(payload.len()).unwrap();
        assert!(length <= 0x00ff_ffff);
        let mut header = [0_u8; 9];
        header[..3].copy_from_slice(&length.to_be_bytes()[1..]);
        header[3] = kind;
        header[4] = flags;
        header[5..].copy_from_slice(&id.to_be_bytes());
        self.socket.write_all(&header).unwrap();
        self.socket.write_all(payload).unwrap();
    }

    fn request(&mut self, id: u32, path: &str, service: &str, token: Option<&str>, timeout: bool) {
        assert!(id > self.latest_stream && id % 2 == 1);
        self.latest_stream = id;
        self.replies.insert(id, Reply::default());
        let mut headers = Vec::new();
        for (name, value) in [
            (":method", "POST"), (":scheme", "http"), (":authority", "localhost"),
            (":path", path), ("content-type", "application/grpc"), ("te", "trailers"),
        ] {
            literal(&mut headers, name, value);
        }
        if let Some(token) = token {
            literal(&mut headers, "authorization", &format!("Bearer {token}"));
        }
        if timeout { literal(&mut headers, "grpc-timeout", "500m"); }
        // Independent golden request encoding: field 1, short UTF-8 service.
        assert!(service.len() < 128);
        let mut body = vec![0];
        body.extend_from_slice(&u32::try_from(service.len() + 2).unwrap().to_be_bytes());
        body.push(10);
        body.push(u8::try_from(service.len()).unwrap());
        body.extend_from_slice(service.as_bytes());
        self.send(1, 4, id, &headers);
        self.send(0, 1, id, &body);
    }

    fn frame(&mut self) -> (u8, u8, u32, Vec<u8>) {
        let mut header = [0_u8; 9];
        self.socket.read_exact(&mut header).expect("native health frame");
        let length = (usize::from(header[0]) << 16)
            | (usize::from(header[1]) << 8) | usize::from(header[2]);
        assert!(length <= 16 * 1024, "bounded native fixture frame");
        let mut payload = vec![0; length];
        self.socket.read_exact(&mut payload).unwrap();
        (header[3], header[4], u32::from_be_bytes(header[5..].try_into().unwrap()) & 0x7fff_ffff, payload)
    }

    fn step(&mut self) -> bool {
        let (kind, flags, id, mut payload) = self.frame();
        match kind {
            4 if flags & 1 == 0 => self.send(4, 1, 0, &[]),
            6 if flags & 1 == 0 => self.send(6, 1, 0, &payload),
            6 => return payload == b"health!!",
            0 => {
                assert_eq!(flags & 8, 0, "fixture emits unpadded DATA");
                let reply = self.replies.get_mut(&id).expect("known health stream");
                assert!(reply.data.len() + payload.len() <= 1024, "bounded unread fixture data");
                reply.data.extend_from_slice(&payload);
                reply.ended |= flags & 1 != 0;
            }
            1 => {
                assert_eq!(flags & (8 | 32), 0, "fixture emits plain HEADERS");
                let mut last = flags;
                while last & 4 == 0 {
                    let (kind, flags, continuation_id, continuation) = self.frame();
                    assert_eq!((kind, continuation_id), (9, id));
                    assert!(payload.len() + continuation.len() <= 16 * 1024);
                    payload.extend_from_slice(&continuation);
                    last = flags;
                }
                let headers = self.decoder.decode(&mut Bytes::from(payload)).unwrap();
                let reply = self.replies.get_mut(&id).expect("known health headers");
                for header in headers {
                    if header.name == ":status" { assert_eq!(header.value, "200"); }
                    if header.name == "grpc-status" {
                        assert!(reply.status.replace(header.value).is_none(), "duplicate grpc-status");
                    }
                }
                reply.ended |= flags & 1 != 0;
            }
            3 => {
                let reply = self.replies.get_mut(&id).unwrap();
                reply.reset = Some(u32::from_be_bytes(payload.try_into().unwrap()));
                reply.ended = true;
            }
            7 => panic!("unexpected health GOAWAY: {payload:?}"),
            _ => {}
        }
        false
    }

    fn message(&mut self, id: u32) -> Vec<u8> {
        for _ in 0..512 {
            let reply = self.replies.get_mut(&id).unwrap();
            if reply.data.len() >= 5 {
                assert_eq!(reply.data[0], 0, "identity health message");
                let length = u32::from_be_bytes(reply.data[1..5].try_into().unwrap()) as usize;
                assert!(length <= 2, "canonical status protobuf is at most two bytes");
                if reply.data.len() >= length + 5 {
                    let bytes = reply.data[5..length + 5].to_vec();
                    drop(reply.data.drain(..length + 5));
                    return bytes;
                }
            }
            assert!(!reply.ended, "health stream ended before its expected message");
            self.step();
        }
        panic!("no health message within fixture frame budget");
    }

    fn finish(&mut self, id: u32, status: &str) {
        for _ in 0..512 {
            if self.replies[&id].ended {
                assert_eq!(self.replies[&id].reset, None);
                assert_eq!(self.replies[&id].status.as_deref(), Some(status));
                assert!(self.replies[&id].data.is_empty(), "unconsumed message bytes");
                return;
            }
            self.step();
        }
        panic!("no health terminal within fixture frame budget");
    }

    fn ping_barrier(&mut self) {
        self.send(6, 0, 0, b"health!!");
        for _ in 0..512 {
            if self.step() { return; }
        }
        panic!("no health PING acknowledgement");
    }
}

fn literal(bytes: &mut Vec<u8>, name: &str, value: &str) {
    assert!(name.len() < 128 && value.len() < 128);
    bytes.push(0);
    bytes.push(u8::try_from(name.len()).unwrap());
    bytes.extend_from_slice(name.as_bytes());
    bytes.push(u8::try_from(value.len()).unwrap());
    bytes.extend_from_slice(value.as_bytes());
}

fn event(events: &Receiver<WatchEvent>, expected: WatchEvent) {
    // Multiple updates can leave earlier Parked receipts; never infer a source
    // retirement from timing or from a different generation's receipt.
    for _ in 0..16 {
        let observed = events.recv_timeout(Duration::from_secs(3)).expect("health source witness");
        if observed == expected { return; }
        assert!(matches!(observed, WatchEvent::Parked(_)), "unexpected retirement: {observed:?}");
    }
    panic!("missing expected health source event: {expected:?}");
}

fn run_case<F>(multithread: bool, health: HealthService, window: u32, client: F)
where
    F: FnOnce(&mut Peer, &HealthService, &HealthRpcService, &Receiver<WatchEvent>) + Send + 'static,
{
    let rpc = health.rpc_service(1);
    let observed_rpc = rpc.clone();
    let (events, observed_events) = sync_channel(32);
    let server = Arc::new(Server::builder().add_service(WitnessService {
        rpc,
        events,
        next: AtomicUsize::new(1),
    }).build());
    let runtime = if multithread {
        RuntimeBuilder::new().worker_threads(2).build().unwrap()
    } else {
        RuntimeBuilder::current_thread().build().unwrap()
    };
    let handle = runtime.handle().clone();
    let completed = Arc::new(AtomicBool::new(false));
    let observed_completion = Arc::clone(&completed);
    let _result = runtime.block_on(runtime.handle().spawn(async move {
        let listener = server.bind_registered_streaming_http2(
            "127.0.0.1:0",
            HostPolicy::allow_all(),
            ServerStreamingConfig {
                frame_capacity: NonZeroUsize::MIN,
                max_frame_bytes: NonZeroUsize::new(7).unwrap(),
                max_trailer_bytes: 1024,
                terminal_timeout: Duration::from_secs(1),
            },
        ).await.unwrap();
        let address = listener.local_addr().unwrap();
        let signal = listener.shutdown_signal();
        let in_flight = listener.in_flight_requests();
        let final_rpc = observed_rpc.clone();
        let peer = std::thread::spawn(move || {
            let _stop = StopOnDrop(signal);
            let mut peer = Peer::connect(address, window);
            client(&mut peer, &health, &observed_rpc, &observed_events);
        });
        let served = listener.run_produced(&handle).await;
        peer.join().expect("native health wire assertions");
        served.expect("native health listener shutdown");
        assert_eq!(final_rpc.active_watches(), 0);
        assert_eq!(in_flight.load(Ordering::Acquire), 0);
        completed.store(true, Ordering::Release);
    }));
    assert!(observed_completion.load(Ordering::Acquire), "native health task did not complete assertions");
}

#[test]
fn native_health_check_watch_updates_reset_and_same_connection_recovery() {
    for multithread in [false, true] {
        let health = HealthService::with_auth_mode(HealthAuthMode::bearer_token("secret"));
        health.set_status("svc", ServingStatus::Serving);
        run_case(multithread, health, 65_535, |peer, health, rpc, events| {
            peer.request(1, CHECK_PATH, "svc", Some("secret"), false);
            assert_eq!(peer.message(1), b"\x08\x01");
            peer.finish(1, "0");
            peer.request(3, WATCH_PATH, "svc", Some("secret"), false);
            assert_eq!(peer.message(3), b"\x08\x01");
            event(events, WatchEvent::Parked(1));
            assert_eq!(rpc.active_watches(), 1);
            health.set_status("svc", ServingStatus::NotServing);
            assert_eq!(peer.message(3), b"\x08\x02");
            event(events, WatchEvent::Parked(1));
            health.clear_status("svc");
            assert_eq!(peer.message(3), b"\x08\x03");
            event(events, WatchEvent::Parked(1));
            peer.send(3, 0, 3, &8_u32.to_be_bytes());
            event(events, WatchEvent::Retired(1));
            assert_eq!(rpc.active_watches(), 0);
            health.set_status("svc", ServingStatus::Serving);
            peer.request(5, CHECK_PATH, "svc", Some("secret"), false);
            assert_eq!(peer.message(5), b"\x08\x01");
            peer.finish(5, "0");
            peer.request(7, WATCH_PATH, "svc", Some("secret"), false);
            assert_eq!(peer.message(7), b"\x08\x01");
            event(events, WatchEvent::Parked(2));
            peer.send(3, 0, 7, &8_u32.to_be_bytes());
            event(events, WatchEvent::Retired(2));
        });
    }
}

#[test]
fn native_health_auth_and_unknown_check_fail_without_allocating_watch_capacity() {
    let health = HealthService::with_auth_mode(HealthAuthMode::bearer_token("secret"));
    run_case(false, health, 65_535, |peer, _, rpc, _| {
        peer.request(1, WATCH_PATH, "missing", None, false);
        peer.finish(1, "16");
        peer.request(3, WATCH_PATH, "missing", Some("wrong"), false);
        peer.finish(3, "16");
        assert_eq!(rpc.active_watches(), 0);
        peer.request(5, CHECK_PATH, "missing", Some("secret"), false);
        peer.finish(5, "7"); // Preserve registry anti-enumeration policy.
        assert_eq!(rpc.active_watches(), 0);
    });
}

#[test]
fn native_zero_credit_watch_saturation_still_allows_check_and_cancel() {
    let health = HealthService::with_auth_mode(HealthAuthMode::bearer_token("secret"));
    health.set_status("svc", ServingStatus::Serving);
    run_case(true, health, 0, |peer, health, rpc, events| {
        peer.request(1, WATCH_PATH, "svc", Some("secret"), false);
        event(events, WatchEvent::Parked(1));
        peer.ping_barrier();
        assert!(peer.replies[&1].data.is_empty(), "no DATA without peer credit");
        health.set_status("svc", ServingStatus::NotServing);
        peer.request(3, WATCH_PATH, "svc", Some("secret"), false);
        peer.finish(3, "8");
        assert_eq!(rpc.active_watches(), 1);
        peer.request(5, CHECK_PATH, "svc", Some("secret"), false);
        peer.send(8, 0, 5, &7_u32.to_be_bytes());
        assert_eq!(peer.message(5), b"\x08\x02");
        peer.finish(5, "0");
        peer.send(3, 0, 1, &8_u32.to_be_bytes());
        event(events, WatchEvent::Retired(1));
        assert_eq!(rpc.active_watches(), 0);
        peer.request(7, WATCH_PATH, "svc", Some("secret"), false);
        peer.send(8, 0, 7, &7_u32.to_be_bytes());
        assert_eq!(peer.message(7), b"\x08\x02");
        event(events, WatchEvent::Parked(2));
        peer.send(3, 0, 7, &8_u32.to_be_bytes());
        event(events, WatchEvent::Retired(2));
    });
}

#[test]
fn native_health_deadline_retires_parked_watch_with_exact_status() {
    let health = HealthService::with_auth_mode(HealthAuthMode::bearer_token("secret"));
    run_case(false, health, 65_535, |peer, _, rpc, events| {
        peer.request(1, WATCH_PATH, "missing", Some("secret"), true);
        assert_eq!(peer.message(1), b"\x08\x03");
        event(events, WatchEvent::Parked(1));
        peer.finish(1, "4");
        event(events, WatchEvent::Retired(1));
        assert_eq!(rpc.active_watches(), 0);
    });
}
