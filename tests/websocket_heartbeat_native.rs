//! Native heartbeat progress with an independent minimal RFC 6455 peer.
//! Pending witnesses come from the real TCP transport, never synthetic stalls.

#![cfg(all(not(target_arch = "wasm32"), feature = "test-internals"))]

use asupersync::Cx;
use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use asupersync::net::TcpStream;
use asupersync::net::websocket::{Message, WebSocket, WebSocketAcceptor, WebSocketConfig, WsError};
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::sync::Notify;
use asupersync::types::CancelKind;
use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

const INTERVAL: Duration = Duration::from_millis(80);
const WATCHDOG: Duration = Duration::from_secs(3);
const UPGRADE: &[u8] = b"GET /heartbeat HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

#[derive(Clone, Copy, Debug)]
enum Role {
    Client,
    Server,
    Split,
}

#[derive(Clone, Copy, Debug)]
enum Behavior {
    Respond,
    Silent,
    WrongPong,
    Resume,
    Cancel,
    Disabled,
}

#[derive(Default)]
struct Witness {
    reads: AtomicUsize,
    writes: AtomicUsize,
    drops: AtomicUsize,
    pings: AtomicUsize,
    parked: Notify,
}

struct Socket {
    inner: TcpStream,
    witness: Arc<Witness>,
}

impl AsyncRead for Socket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if result.is_pending() {
            self.witness.reads.fetch_add(1, Ordering::AcqRel);
            self.witness.parked.notify_one();
        }
        result
    }
}

impl AsyncWrite for Socket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, bytes);
        if result.is_pending() {
            self.witness.writes.fetch_add(1, Ordering::AcqRel);
            self.witness.parked.notify_one();
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        self.witness.drops.fetch_add(1, Ordering::AcqRel);
    }
}

fn pair() -> (std::net::TcpStream, std::net::TcpStream) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    server.set_nonblocking(true).unwrap();
    peer.set_read_timeout(Some(WATCHDOG)).unwrap();
    peer.set_write_timeout(Some(WATCHDOG)).unwrap();
    (server, peer)
}

fn native_runtime(workers: usize) -> Runtime {
    let builder = if workers == 0 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread().worker_threads(workers)
    };
    builder
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap()
}

fn assert_retired(runtime: &Runtime) {
    let started = Instant::now();
    while !runtime.is_quiescent() {
        assert!(
            started.elapsed() < WATCHDOG,
            "WebSocket owner did not retire"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        runtime
            .task_inspector(Default::default())
            .list_tasks()
            .is_empty()
    );
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert_eq!(runtime.draining_region_count(), 0);
}

// The independent peer supports only the small control/text frames used here.
fn receive_frame(peer: &mut std::net::TcpStream, masked: bool) -> Option<(u8, Vec<u8>)> {
    let mut first = [0_u8; 1];
    if peer.read(&mut first).expect("peer frame opcode") == 0 {
        return None;
    }
    let mut second = [0_u8; 1];
    peer.read_exact(&mut second).unwrap();
    assert_eq!(first[0] & 0xf0, 0x80, "FIN and no unsupported RSV bits");
    assert_eq!(second[0] & 0x80 != 0, masked, "correct role masking");
    let length = usize::from(second[0] & 0x7f);
    assert!(length <= 125, "heartbeat control payload bound");
    let mut mask = [0_u8; 4];
    if masked {
        peer.read_exact(&mut mask).unwrap();
    }
    let mut payload = vec![0_u8; length];
    peer.read_exact(&mut payload).unwrap();
    if masked {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }
    Some((first[0] & 0x0f, payload))
}

fn send_frame(peer: &mut std::net::TcpStream, masked: bool, opcode: u8, payload: &[u8]) {
    assert!(payload.len() <= 125);
    let mut frame = vec![
        0x80 | opcode,
        payload.len() as u8 | if masked { 0x80 } else { 0 },
    ];
    let mask = [0x31, 0x47, 0x53, 0x61];
    if masked {
        frame.extend_from_slice(&mask);
    }
    frame.extend(payload.iter().enumerate().map(|(index, byte)| {
        if masked {
            byte ^ mask[index % 4]
        } else {
            *byte
        }
    }));
    peer.write_all(&frame).unwrap();
}

fn run_peer(
    mut peer: std::net::TcpStream,
    role: Role,
    behavior: Behavior,
    witness: Arc<Witness>,
) -> usize {
    let server = matches!(role, Role::Server);
    if server {
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") {
            let mut byte = [0_u8; 1];
            peer.read_exact(&mut byte).expect("HTTP upgrade response");
            response.push(byte[0]);
            assert!(response.len() < 4096);
        }
        assert!(response.starts_with(b"HTTP/1.1 101 "));
    }
    if matches!(behavior, Behavior::Disabled) {
        std::thread::sleep(INTERVAL * 3);
        send_frame(&mut peer, server, 1, b"alive");
    }
    let mut previous = None;
    while let Some((opcode, payload)) = receive_frame(&mut peer, !server) {
        match opcode {
            9 => {
                assert_eq!(payload.len(), 16);
                assert_ne!(
                    previous.as_ref(),
                    Some(&payload),
                    "each Ping has a fresh correlation payload"
                );
                previous = Some(payload.clone());
                let count = witness.pings.fetch_add(1, Ordering::AcqRel) + 1;
                match behavior {
                    Behavior::Respond => {
                        send_frame(&mut peer, server, 10, &payload);
                        if count == 3 {
                            send_frame(&mut peer, server, 1, b"alive");
                        }
                    }
                    Behavior::WrongPong => send_frame(&mut peer, server, 10, b"unrelated pong"),
                    Behavior::Resume => send_frame(&mut peer, server, 1, b"pause"),
                    Behavior::Silent | Behavior::Cancel => {}
                    Behavior::Disabled => panic!("disabled heartbeat emitted a Ping"),
                }
            }
            8 => {}
            _ => panic!("unexpected client opcode {opcode}"),
        }
    }
    witness.pings.load(Ordering::Acquire)
}

async fn drop_pending_recv<F>(future: F, witness: &Witness)
where
    F: Future<Output = Result<Option<Message>, WsError>>,
{
    let before = witness.reads.load(Ordering::Acquire);
    let mut future = std::pin::pin!(future);
    poll_fn(|task| {
        assert!(
            future.as_mut().poll(task).is_pending(),
            "receive must park before abandoning its borrowing wait"
        );
        Poll::Ready(())
    })
    .await;
    assert!(
        witness.reads.load(Ordering::Acquire) > before,
        "Pending came from an actual TCP read"
    );
}

fn scenario(workers: usize, role: Role, behavior: Behavior) {
    let (server, peer) = pair();
    let witness = Arc::new(Witness::default());
    let peer_witness = Arc::clone(&witness);
    let peer = std::thread::spawn(move || run_peer(peer, role, behavior, peer_witness));
    let runtime = native_runtime(workers);
    let handle = runtime.handle();
    let started = Instant::now();
    runtime.block_on(async {
        let owner = Arc::new(Mutex::new(None::<Cx>));
        let task_owner = Arc::clone(&owner);
        let task_witness = Arc::clone(&witness);
        let mut task = handle.try_spawn(async move {
            let cx = Cx::current().unwrap();
            *task_owner.lock().unwrap() = Some(cx.clone());
            let socket = Socket { inner: TcpStream::from_std(server).unwrap(), witness: Arc::clone(&task_witness) };
            let interval = (!matches!(behavior, Behavior::Disabled)).then_some(INTERVAL);
            let (result, closed) = match role {
                Role::Client => {
                    let mut ws = WebSocket::from_upgraded(socket, WebSocketConfig::new().ping_interval(interval));
                    if matches!(behavior, Behavior::Resume) {
                        assert!(matches!(ws.recv(&cx).await, Ok(Some(Message::Text(text))) if text == "pause"));
                        drop_pending_recv(ws.recv(&cx), &task_witness).await;
                    }
                    let result = ws.recv(&cx).await;
                    (result, ws.is_closed())
                }
                Role::Server => {
                    let mut ws = WebSocketAcceptor::new().ping_interval(interval).close_timeout(INTERVAL)
                        .accept(&cx, UPGRADE, socket).await.unwrap();
                    if matches!(behavior, Behavior::Resume) {
                        assert!(matches!(ws.recv(&cx).await, Ok(Some(Message::Text(text))) if text == "pause"));
                        drop_pending_recv(ws.recv(&cx), &task_witness).await;
                    }
                    let result = ws.recv(&cx).await;
                    (result, ws.is_closed())
                }
                Role::Split => {
                    let ws = WebSocket::from_upgraded(socket, WebSocketConfig::new().ping_interval(interval));
                    let (mut read, write) = ws.split();
                    if matches!(behavior, Behavior::Resume) {
                        assert!(matches!(read.recv(&cx).await, Ok(Some(Message::Text(text))) if text == "pause"));
                        drop_pending_recv(read.recv(&cx), &task_witness).await;
                        let mut ws = read.reunite(write).expect("heartbeat owner reunites");
                        let result = ws.recv(&cx).await;
                        (result, ws.is_closed())
                    } else {
                        let result = read.recv(&cx).await;
                        let closed = read.is_closed();
                        drop(write);
                        (result, closed)
                    }
                }
            };
            match behavior {
                Behavior::Respond | Behavior::Disabled => {
                    assert!(matches!(result, Ok(Some(Message::Text(ref text))) if text == "alive"), "unexpected result: {result:?}");
                    assert!(!closed);
                    assert!(!cx.is_cancel_requested());
                }
                Behavior::Silent | Behavior::WrongPong | Behavior::Resume => {
                    assert!(matches!(result, Err(WsError::Io(ref error)) if error.kind() == std::io::ErrorKind::TimedOut), "unexpected result: {result:?}");
                    assert!(closed, "heartbeat expiry is terminal");
                    assert!(!cx.is_cancel_requested(), "local heartbeat cannot cancel its owner task");
                }
                Behavior::Cancel => {
                    assert!(matches!(result, Err(WsError::Io(ref error)) if error.kind() == std::io::ErrorKind::Interrupted), "unexpected result: {result:?}");
                    assert_eq!(cx.cancel_reason().unwrap().kind, CancelKind::User);
                }
            }
        }).unwrap();
        asupersync::time::timeout(asupersync::time::wall_now(), WATCHDOG,
            witness.parked.wait_until(|| witness.reads.load(Ordering::Acquire) > 0),
        ).await.expect("recv must reach a real Pending socket read");
        if matches!(behavior, Behavior::Cancel) {
            owner.lock().unwrap().as_ref().unwrap().cancel_fast(CancelKind::User);
        }
        asupersync::time::timeout(asupersync::time::wall_now(), WATCHDOG, &mut task)
            .await.expect("heartbeat owner must finish without peer release");
        assert_eq!(witness.drops.load(Ordering::Acquire), 1);
    });
    let pings = peer.join().expect("independent peer saw transport EOF");
    if matches!(behavior, Behavior::Respond) {
        assert_eq!(pings, 3);
    } else if matches!(
        behavior,
        Behavior::Silent | Behavior::WrongPong | Behavior::Resume
    ) {
        assert_eq!(pings, 1, "unmatched/missing Pong cannot rearm heartbeat");
    }
    assert_retired(&runtime);
    eprintln!(
        "{{\"bead\":\"asupersync-bi2462.120\",\"workers\":{workers},\"role\":\"{role:?}\",\"behavior\":\"{behavior:?}\",\"pending_reads\":{},\"pings\":{pings},\"elapsed_ms\":{},\"transport_drops\":1}}",
        witness.reads.load(Ordering::Acquire),
        started.elapsed().as_millis()
    );
}

#[test]
fn native_idle_websockets_ping_match_pongs_and_expire_silent_peers() {
    for workers in [0, 1, 2] {
        for role in [Role::Client, Role::Server, Role::Split] {
            for behavior in [
                Behavior::Respond,
                Behavior::Silent,
                Behavior::WrongPong,
                Behavior::Resume,
            ] {
                scenario(workers, role, behavior);
            }
        }
    }
}

#[test]
fn native_heartbeat_waits_cancel_and_can_be_disabled() {
    for workers in [0, 1, 2] {
        for role in [Role::Client, Role::Server, Role::Split] {
            for behavior in [Behavior::Cancel, Behavior::Disabled] {
                scenario(workers, role, behavior);
            }
        }
    }
}

fn fill_send_queue(socket: &mut std::net::TcpStream) -> usize {
    socket2::SockRef::from(&*socket)
        .set_send_buffer_size(4096)
        .unwrap();
    let started = Instant::now();
    let mut blocked_since = None;
    let mut bytes = 0;
    loop {
        assert!(started.elapsed() < WATCHDOG, "TCP send queue did not fill");
        match socket.write(&[b'x'; 16 * 1024]) {
            Ok(0) => panic!("peer closed during setup"),
            Ok(n) => {
                bytes += n;
                blocked_since = None;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                let blocked = blocked_since.get_or_insert_with(Instant::now);
                if blocked.elapsed() >= Duration::from_millis(50) {
                    return bytes;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("fill send queue: {error}"),
        }
    }
}

#[test]
fn heartbeat_deadline_releases_a_real_nonreading_peer_write() {
    for workers in [0, 1, 2] {
        for role in [Role::Client, Role::Server, Role::Split] {
            let (server, peer) = pair();
            socket2::SockRef::from(&peer)
                .set_recv_buffer_size(4096)
                .unwrap();
            let mut fill = server.try_clone().unwrap();
            let witness = Arc::new(Witness::default());
            let runtime = native_runtime(workers);
            let handle = runtime.handle();
            runtime.block_on(async {
                let task_witness = Arc::clone(&witness);
                let mut task = handle.try_spawn(async move {
                    let cx = Cx::current().unwrap();
                    let socket = Socket { inner: TcpStream::from_std(server).unwrap(), witness: task_witness };
                    let (result, closed, filled) = match role {
                        Role::Client => {
                            let mut ws = WebSocket::from_upgraded(socket, WebSocketConfig::new().ping_interval(Some(INTERVAL)));
                            let filled = fill_send_queue(&mut fill);
                            drop(fill);
                            let result = ws.recv(&cx).await;
                            (result, ws.is_closed(), filled)
                        }
                        Role::Server => {
                            let mut ws = WebSocketAcceptor::new().ping_interval(Some(INTERVAL))
                                .accept(&cx, UPGRADE, socket).await.unwrap();
                            let filled = fill_send_queue(&mut fill);
                            drop(fill);
                            let result = ws.recv(&cx).await;
                            (result, ws.is_closed(), filled)
                        }
                        Role::Split => {
                            let ws = WebSocket::from_upgraded(socket, WebSocketConfig::new().ping_interval(Some(INTERVAL)));
                            let filled = fill_send_queue(&mut fill);
                            drop(fill);
                            let (mut read, write) = ws.split();
                            let result = read.recv(&cx).await;
                            let closed = read.is_closed();
                            drop(write);
                            (result, closed, filled)
                        }
                    };
                    assert!(matches!(result, Err(WsError::Io(ref error)) if error.kind() == std::io::ErrorKind::TimedOut), "unexpected result: {result:?}");
                    assert!(closed);
                    assert!(!cx.is_cancel_requested());
                    filled
                }).unwrap();
                asupersync::time::timeout(asupersync::time::wall_now(), WATCHDOG,
                    witness.parked.wait_until(|| witness.writes.load(Ordering::Acquire) > 0),
                ).await.expect("heartbeat Ping reached actual TCP write backpressure");
                let started = Instant::now();
                let verdict = asupersync::time::timeout(asupersync::time::wall_now(), WATCHDOG, &mut task).await;
                // A nonreader remains open until the deadline verdict.
                drop(peer);
                let filled = verdict.expect("Ping write must obey heartbeat deadline");
                assert_eq!(witness.drops.load(Ordering::Acquire), 1);
                eprintln!("{{\"bead\":\"asupersync-bi2462.120\",\"scenario\":\"parked-ping-write\",\"workers\":{workers},\"role\":\"{role:?}\",\"filled_bytes\":{filled},\"pending_writes\":{},\"elapsed_ms\":{},\"transport_drops\":1}}", witness.writes.load(Ordering::Acquire), started.elapsed().as_millis());
            });
            assert_retired(&runtime);
        }
    }
}

#[test]
fn split_heartbeat_expiry_wakes_the_writer_holding_its_permit() {
    for workers in [0, 1, 2] {
        let (mut server, peer) = pair();
        socket2::SockRef::from(&peer)
            .set_recv_buffer_size(4096)
            .unwrap();
        let filled = fill_send_queue(&mut server);
        let witness = Arc::new(Witness::default());
        let runtime = native_runtime(workers);
        let handle = runtime.handle();
        runtime.block_on(async {
            let socket = Socket { inner: TcpStream::from_std(server).unwrap(), witness: Arc::clone(&witness) };
            let ws = WebSocket::from_upgraded(socket, WebSocketConfig::new().ping_interval(Some(INTERVAL)));
            let (mut read, mut write) = ws.split();
            let mut writing = handle.try_spawn(async move {
                let cx = Cx::current().unwrap();
                let result = write.send(&cx, Message::binary(vec![7; 16 * 1024])).await;
                assert!(!cx.is_cancel_requested());
                result
            }).unwrap();
            asupersync::time::timeout(asupersync::time::wall_now(), WATCHDOG,
                witness.parked.wait_until(|| witness.writes.load(Ordering::Acquire) > 0),
            ).await.expect("application writer must really park while holding its permit");
            let mut reading = handle.try_spawn(async move {
                let cx = Cx::current().unwrap();
                let result = read.recv(&cx).await;
                assert!(read.is_closed());
                assert!(!cx.is_cancel_requested());
                result
            }).unwrap();
            let started = Instant::now();
            let read_verdict = asupersync::time::timeout(asupersync::time::wall_now(), WATCHDOG, &mut reading).await;
            let write_verdict = asupersync::time::timeout(asupersync::time::wall_now(), WATCHDOG, &mut writing).await;
            drop(peer);
            let read_result = read_verdict.expect("heartbeat may not wait forever for writer permit");
            let write_result = write_verdict.expect("heartbeat expiry must wake the already parked writer");
            assert!(matches!(read_result, Err(WsError::Io(ref error)) if error.kind() == std::io::ErrorKind::TimedOut));
            assert!(matches!(write_result, Err(WsError::Io(ref error)) if error.kind() == std::io::ErrorKind::TimedOut));
            assert_eq!(witness.drops.load(Ordering::Acquire), 1);
            eprintln!("{{\"bead\":\"asupersync-bi2462.120\",\"scenario\":\"parked-split-writer-permit\",\"workers\":{workers},\"filled_bytes\":{filled},\"pending_writes\":{},\"elapsed_ms\":{},\"transport_drops\":1}}", witness.writes.load(Ordering::Acquire), started.elapsed().as_millis());
        });
        assert_retired(&runtime);
    }
}

#[test]
fn splitting_after_abandoned_ping_write_preserves_and_flushes_the_ping() {
    for workers in [0, 1, 2] {
        let (mut server, mut peer) = pair();
        socket2::SockRef::from(&peer)
            .set_recv_buffer_size(4096)
            .unwrap();
        let filled = fill_send_queue(&mut server);
        let (release, released) = std::sync::mpsc::channel();
        let peer = std::thread::spawn(move || {
            released
                .recv_timeout(WATCHDOG)
                .expect("owner split only after actual Pending Ping write");
            let mut prefilled = vec![0_u8; filled];
            peer.read_exact(&mut prefilled).unwrap();
            assert!(prefilled.iter().all(|byte| *byte == b'x'));
            let (opcode, payload) = receive_frame(&mut peer, true).expect("retained Ping frame");
            assert_eq!(opcode, 9);
            assert_eq!(payload.len(), 16);
            send_frame(&mut peer, false, 10, &payload);
            send_frame(&mut peer, false, 1, b"alive");
            assert!(
                receive_frame(&mut peer, true).is_none(),
                "no duplicate Ping after resuming"
            );
        });
        let runtime = native_runtime(workers);
        let handle = runtime.handle();
        let witness = Arc::new(Witness::default());
        runtime.block_on(async {
            let task_witness = Arc::clone(&witness);
            let mut task = handle
                .try_spawn(async move {
                    let cx = Cx::current().unwrap();
                    let socket = Socket {
                        inner: TcpStream::from_std(server).unwrap(),
                        witness: Arc::clone(&task_witness),
                    };
                    // A wider allowance covers deliberately draining the full TCP
                    // queue after the writer has demonstrably parked.
                    let mut ws = WebSocket::from_upgraded(
                        socket,
                        WebSocketConfig::new().ping_interval(Some(Duration::from_millis(500))),
                    );
                    {
                        let mut receiving = std::pin::pin!(ws.recv(&cx));
                        poll_fn(|task| {
                            assert!(
                                receiving.as_mut().poll(task).is_pending(),
                                "peer is silent and unread"
                            );
                            if task_witness.writes.load(Ordering::Acquire) > 0 {
                                Poll::Ready(())
                            } else {
                                Poll::Pending
                            }
                        })
                        .await;
                    }
                    let (mut read, write) = ws.split();
                    release.send(()).unwrap();
                    let result = read.recv(&cx).await;
                    assert!(
                        matches!(result, Ok(Some(Message::Text(ref text))) if text == "alive"),
                        "retained Ping must flush after split: {result:?}"
                    );
                    assert!(read.is_open());
                    drop(write);
                })
                .unwrap();
            asupersync::time::timeout(asupersync::time::wall_now(), WATCHDOG, &mut task)
                .await
                .expect("split reader must complete the previously queued Ping");
            assert!(witness.writes.load(Ordering::Acquire) > 0);
            assert_eq!(witness.drops.load(Ordering::Acquire), 1);
        });
        peer.join()
            .expect("independent peer saw one complete Ping and EOF");
        assert_retired(&runtime);
        eprintln!(
            "{{\"bead\":\"asupersync-bi2462.120\",\"scenario\":\"abandoned-ping-write-then-split\",\"workers\":{workers},\"filled_bytes\":{filled},\"pending_writes\":{},\"transport_drops\":1}}",
            witness.writes.load(Ordering::Acquire)
        );
    }
}
