//! Real socket/runtime coverage for the additive native streaming client.
//! br-asupersync-server-stack-hardening-eeexl1.10; no loopback-RPC simulation.

use super::*;
use crate::grpc::health::{HealthAuthMode, HealthService, ServingStatus};
use crate::grpc::server::{Server, ServerStreamingConfig};
use crate::grpc::service::{NamedService, RegisteredServerStream, ServiceDescriptor, ServiceHandler, ServiceStreamingFuture};
use crate::http::h1::server::HostPolicy;
use crate::net::TcpStream;
use crate::runtime::RuntimeBuilder;
use crate::server::shutdown::ShutdownSignal;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::sync_channel;

struct StopOnDrop(ShutdownSignal);
impl Drop for StopOnDrop { fn drop(&mut self) { self.0.trigger_immediate(); } }

fn run_server<S, F, Fut>(multithread: bool, service: S, client: F)
where
    S: NamedService + ServiceHandler + 'static,
    F: FnOnce(Cx, SocketAddr) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let runtime = if multithread {
        RuntimeBuilder::new().worker_threads(2).build().unwrap()
    } else { RuntimeBuilder::current_thread().build().unwrap() };
    let handle = runtime.handle().clone();
    let complete = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&complete);
    runtime.block_on(runtime.handle().spawn(async move {
        let server = Arc::new(Server::builder().add_service(service).build());
        let listener = server.bind_registered_streaming_http2("127.0.0.1:0", HostPolicy::allow_all(),
            ServerStreamingConfig {
                frame_capacity: NonZeroUsize::new(2).unwrap(),
                max_frame_bytes: NonZeroUsize::new(1024).unwrap(),
                max_trailer_bytes: 1024,
                terminal_timeout: Duration::from_secs(2),
            }).await.unwrap();
        let address = listener.local_addr().unwrap();
        let stop = StopOnDrop(listener.shutdown_signal());
        let requests = listener.in_flight_requests();
        let client_done = Arc::new(AtomicBool::new(false));
        let observed_client = Arc::clone(&client_done);
        let task = handle.spawn(async move {
            let _stop = stop;
            client(Cx::current().expect("native client context"), address).await;
            client_done.store(true, Ordering::Release);
        });
        let result = listener.run_produced(&handle).await;
        let _ = task.await;
        result.expect("native streaming server shutdown");
        assert!(observed_client.load(Ordering::Acquire), "client assertions did not finish");
        assert_eq!(requests.load(Ordering::Acquire), 0);
        complete.store(true, Ordering::Release);
    }));
    assert!(observed.load(Ordering::Acquire), "native test root did not finish");
}

#[test]
fn native_client_consumes_authenticated_health_watch_and_close_releases_server_slot() {
    for multithread in [false, true] {
        let health = HealthService::with_auth_mode(HealthAuthMode::bearer_token("native-secret"));
        health.set_status("svc", ServingStatus::Serving);
        let rpc = health.rpc_service(1);
        let observed = rpc.clone();
        run_server(multithread, rpc, move |cx, address| async move {
            let io = TcpStream::connect_timeout(address, Duration::from_secs(3)).await.unwrap();
            let mut request = Request::new(Bytes::from_static(b"\x0a\x03svc"));
            assert!(request.metadata_mut().insert("authorization", "Bearer native-secret"));
            let mut stream = NativeServerStream::new(&cx, io, "localhost", "/grpc.health.v1.Health/Watch",
                request, IdentityCodec,
                NativeStreamConfig { timeout: Some(Duration::from_secs(5)), ..NativeStreamConfig::default() }).unwrap();
            stream.headers().await.unwrap();
            assert_eq!(stream.message().await.unwrap().unwrap().as_ref(), b"\x08\x01");
            health.set_status("svc", ServingStatus::NotServing);
            assert_eq!(stream.message().await.unwrap().unwrap().as_ref(), b"\x08\x02");
            assert_eq!(observed.active_watches(), 1);
            {
                let mut next = Box::pin(stream.message());
                poll_fn(|task| {
                    assert!(next.as_mut().poll(task).is_pending(), "unchanged Watch must wait");
                    Poll::Ready(())
                }).await;
            }
            stream.cancel();
            assert_eq!(stream.status().unwrap().code(), Code::Cancelled);
            let timer = cx.timer_driver().unwrap();
            crate::time::timeout(timer.now(), Duration::from_secs(3), async {
                while observed.active_watches() != 0 { crate::runtime::yield_now().await; }
            }).await.expect("peer observed EOF and retired actual watch before listener shutdown");
            assert!(!cx.is_cancel_requested(), "closing one call must not cancel its task");
        });
    }
}

struct Values { count: u8, size: usize }
impl NamedService for Values { const NAME: &'static str = "test.Values"; }
impl ServiceHandler for Values {
    fn descriptor(&self) -> &ServiceDescriptor {
        static METHODS: &[crate::grpc::service::MethodDescriptor] = &[
            crate::grpc::service::MethodDescriptor::server_streaming("Watch", "/test.Values/Watch")
        ];
        static DESCRIPTOR: ServiceDescriptor = ServiceDescriptor::new("Values", "test", METHODS);
        &DESCRIPTOR
    }
    fn method_names(&self) -> Vec<&str> { vec!["Watch"] }
    fn call_server_streaming<'a>(&'a self, _: &'a Cx, _: &'a str, request: Request<Bytes>, _: Metadata) -> ServiceStreamingFuture<'a> {
        Box::pin(async move {
            assert_eq!(request.get_ref().as_ref(), b"native-request");
            let mut source = crate::grpc::streaming::StreamingRequest::open();
            for index in 0_u8..self.count { source.push(Bytes::from(vec![index; self.size])).unwrap(); }
            source.close();
            let mut trailers = Metadata::new();
            assert!(trailers.insert_bin("x-receipt-bin", Bytes::from_static(b"exact-receipt")));
            Ok(RegisteredServerStream::new(source).with_trailers(trailers))
        })
    }
}

#[test]
fn native_client_crosses_multiple_h2_windows_and_requires_success_trailers() {
    run_server(true, Values { count: 40, size: 4096 }, |cx, address| async move {
        let io = TcpStream::connect_timeout(address, Duration::from_secs(3)).await.unwrap();
        let mut stream = NativeServerStream::new(&cx, io, "localhost", "/test.Values/Watch",
            Request::new(Bytes::from_static(b"native-request")), IdentityCodec,
            NativeStreamConfig { max_recv_message_size: 4096, timeout: Some(Duration::from_secs(10)), ..NativeStreamConfig::default() }).unwrap();
        // 164,040 framed bytes exceed both initial 65,535-byte windows.
        for index in 0_u8..40 {
            let value = stream.message().await.unwrap().expect("all response messages");
            assert_eq!(value.as_ref(), vec![index; 4096].as_slice());
            assert!(stream.buffered_data_bytes() <= 4096 + 5 + FRAME_BYTES);
            crate::runtime::yield_now().await;
        }
        assert!(stream.message().await.unwrap().is_none());
        assert_eq!(stream.status().unwrap().code(), Code::Ok);
        assert!(matches!(stream.trailers().unwrap().get("x-receipt-bin"),
            Some(MetadataValue::Binary(value)) if value.as_ref() == b"exact-receipt"));
        assert!(stream.message().await.unwrap().is_none());
    });
}

#[test]
fn native_client_assembles_one_message_larger_than_the_initial_flow_window() {
    run_server(false, Values { count: 1, size: 128 * 1024 }, |cx, address| async move {
        let io = TcpStream::connect_timeout(address, Duration::from_secs(3)).await.unwrap();
        let mut stream = NativeServerStream::new(&cx, io, "localhost", "/test.Values/Watch",
            Request::new(Bytes::from_static(b"native-request")), IdentityCodec,
            NativeStreamConfig { max_recv_message_size: 128 * 1024,
                timeout: Some(Duration::from_secs(10)), ..NativeStreamConfig::default() }).unwrap();
        let value = stream.message().await.unwrap().expect("large streamed message");
        assert_eq!(value.len(), 128 * 1024);
        assert!(value.iter().all(|byte| *byte == 0));
        assert!(stream.message().await.unwrap().is_none());
        assert_eq!(stream.status().unwrap().code(), Code::Ok);
    });
}

fn read_request(socket: &mut std::net::TcpStream) {
    let mut preface = [0_u8; 24];
    socket.read_exact(&mut preface).unwrap();
    assert_eq!(&preface, CLIENT_PREFACE);
    let mut body = Vec::new();
    for _ in 0..64 {
        let mut header = [0_u8; 9];
        socket.read_exact(&mut header).unwrap();
        let length = (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2]);
        assert!(length <= FRAME_BYTES);
        let mut payload = vec![0; length];
        socket.read_exact(&mut payload).unwrap();
        if header[3] == 0 {
            body.extend(payload);
            if header[4] & 1 != 0 {
                assert_eq!(body, message(b"native-request"));
                return;
            }
        }
    }
    panic!("native request never ended");
}

#[test]
fn native_client_cross_thread_cancel_wakes_witnessed_partial_message_read() {
    for multithread in [false, true] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let (witness, witnessed) = sync_channel::<Cx>(1);
        let peer = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(std::time::Instant::now() < deadline, "native accept watchdog");
                        std::thread::park_timeout(Duration::from_millis(1));
                    }
                    Err(error) => panic!("native accept: {error}"),
                }
            };
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            read_request(&mut socket);
            let mut response = start();
            response.extend(frame(0, 0, &[0, 0, 0]));
            socket.write_all(&response).unwrap();
            let cx = witnessed.recv_timeout(Duration::from_secs(3)).expect("partial message truly reached Pending");
            cx.cancel_with(CancelKind::User, Some("cross-thread client cancellation"));
            let mut scratch = [0; 1024];
            for _ in 0..32 {
                if socket.read(&mut scratch).unwrap() == 0 { return; }
            }
            panic!("client did not close its owned transport");
        });
        let runtime = if multithread {
            RuntimeBuilder::new().worker_threads(2).build().unwrap()
        } else { RuntimeBuilder::current_thread().build().unwrap() };
        let complete = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&complete);
        runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().unwrap();
            let io = TcpStream::connect_timeout(address, Duration::from_secs(3)).await.unwrap();
            let mut stream = NativeServerStream::new(&cx, io, "localhost", "/test.Values/Watch",
                Request::new(Bytes::from_static(b"native-request")), IdentityCodec,
                NativeStreamConfig { timeout: Some(Duration::from_secs(5)), ..NativeStreamConfig::default() }).unwrap();
            let mut sent = false;
            let result = poll_fn(|task| {
                let result = Pin::new(&mut stream).poll_next(task);
                if result.is_pending() && !sent && stream.buffered_data_bytes() == 3 {
                    witness.try_send(cx.clone()).unwrap();
                    sent = true;
                }
                result
            }).await.expect("cancellation terminal").unwrap_err();
            assert!(sent, "did not witness the partial-message read");
            assert_eq!(result.code(), Code::Cancelled);
            assert_eq!(stream.status().unwrap().code(), Code::Cancelled);
            assert_eq!(stream.buffered_data_bytes(), 0);
            assert!(stream.message().await.unwrap().is_none());
            complete.store(true, Ordering::Release);
        }));
        peer.join().expect("native peer witnessed transport closure");
        assert!(observed.load(Ordering::Acquire), "cancelled client assertions did not finish");
    }
}

// This transport delegates every byte to a real native TCP socket. A controlled
// write/flush gate reproduces adapters whose output cannot advance before input
// is driven (for example, a duplex buffered transport). No response is fabricated
// by the adapter. The peer waits for BOTH an observed Pending and the caller's
// dropped borrowing wait before sending its response.
struct NativeDuplexGate {
    open: AtomicBool,
    parked: AtomicBool,
    witness: std::sync::mpsc::SyncSender<()>,
    wake: Mutex<Option<Waker>>,
    drops: AtomicUsize,
}

impl NativeDuplexGate {
    fn park(&self, task: &Context<'_>) {
        *self.wake.lock().unwrap() = Some(task.waker().clone());
        if !self.parked.swap(true, Ordering::SeqCst) {
            self.witness.try_send(()).expect("one native duplex Pending witness");
        }
    }

    fn release(&self) {
        self.open.store(true, Ordering::SeqCst);
        let wake = self.wake.lock().unwrap().take();
        if let Some(wake) = wake { wake.wake(); }
    }
}

struct NativeDuplexIo {
    inner: TcpStream,
    gate: Arc<NativeDuplexGate>,
    block_flush: bool,
    frame_remaining: usize,
    request_headers: bool,
    headers_written: bool,
}

impl AsyncRead for NativeDuplexIo {
    fn poll_read(self: Pin<&mut Self>, task: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(task, buf);
        if buf.filled().len() > before { this.gate.release(); }
        result
    }
}

impl AsyncWrite for NativeDuplexIo {
    fn poll_write(self: Pin<&mut Self>, task: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.block_flush && this.headers_written && !this.gate.open.load(Ordering::SeqCst) {
            this.gate.park(task);
            return Poll::Pending;
        }
        if this.frame_remaining == 0 {
            // NativeServerStream retains a single encoded frame across writes.
            // Track its remainder so actual partial TCP writes cannot make us
            // mistake payload bytes for another frame header.
            assert!(bytes.len() >= 9);
            this.frame_remaining = bytes.len();
            this.request_headers = bytes[3] == 1 && bytes[4] & 4 != 0;
        }
        let result = Pin::new(&mut this.inner).poll_write(task, bytes);
        if let Poll::Ready(Ok(written)) = &result {
            assert!(*written <= this.frame_remaining);
            this.frame_remaining -= *written;
            if this.frame_remaining == 0 && this.request_headers {
                this.headers_written = true;
            }
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.block_flush && !this.gate.open.load(Ordering::SeqCst) {
            this.gate.park(task);
            return Poll::Pending;
        }
        Pin::new(&mut this.inner).poll_flush(task)
    }

    fn poll_shutdown(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(task)
    }
}

impl Drop for NativeDuplexIo {
    fn drop(&mut self) { self.gate.drops.fetch_add(1, Ordering::SeqCst); }
}

fn duplex_peer_frame(socket: &mut std::net::TcpStream) -> (u8, u8, Vec<u8>) {
    let mut header = [0_u8; 9];
    socket.read_exact(&mut header).expect("native duplex frame header");
    let length = (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2]);
    assert!(length <= FRAME_BYTES);
    let mut payload = vec![0; length];
    socket.read_exact(&mut payload).expect("native duplex frame payload");
    (header[3], header[4], payload)
}

fn duplex_peer_request_head(socket: &mut std::net::TcpStream) {
    let mut preface = [0_u8; 24];
    socket.read_exact(&mut preface).unwrap();
    assert_eq!(&preface, CLIENT_PREFACE);
    for _ in 0..16 {
        let (kind, flags, payload) = duplex_peer_frame(socket);
        if kind == 1 {
            assert_ne!(flags & 4, 0, "bounded fixture headers fit one frame");
            let fields = crate::http::h2::HpackDecoder::new().decode(&mut Bytes::from(payload)).unwrap();
            assert!(fields.iter().any(|header| header.name == ":path" && header.value == "/test.Service/Watch"));
            return;
        }
        assert_eq!(kind, 4, "only initial SETTINGS precede request HEADERS");
    }
    panic!("missing native duplex request headers");
}

fn duplex_peer_request_body(socket: &mut std::net::TcpStream) {
    let mut body = Vec::new();
    for _ in 0..64 {
        let (kind, flags, payload) = duplex_peer_frame(socket);
        assert_ne!(kind, 1, "interrupted wait must not repeat request HEADERS");
        if kind == 0 {
            body.extend(payload);
            assert!(body.len() <= message(b"native-request").len());
            if flags & 1 != 0 {
                assert_eq!(body, message(b"native-request"));
                return;
            }
        }
    }
    panic!("missing native duplex request completion");
}

#[test]
fn native_duplex_pending_write_and_flush_resume_after_interrupted_header_wait() {
    for multithread in [false, true] {
        for block_flush in [false, true] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let (witness, witnessed) = sync_channel(1);
            let (release_peer, peer_released) = sync_channel(1);
            let gate = Arc::new(NativeDuplexGate {
                open: AtomicBool::new(false), parked: AtomicBool::new(false), witness,
                wake: Mutex::new(None), drops: AtomicUsize::new(0),
            });
            let observed_gate = Arc::clone(&gate);
            let peer = std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            assert!(std::time::Instant::now() < deadline, "native duplex accept watchdog");
                            std::thread::park_timeout(Duration::from_millis(1));
                        }
                        Err(error) => panic!("native duplex accept: {error}"),
                    }
                };
                socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
                duplex_peer_request_head(&mut socket);
                if block_flush { duplex_peer_request_body(&mut socket); }
                witnessed.recv_timeout(Duration::from_secs(3)).expect("write/flush actually reached Pending");
                peer_released.recv_timeout(Duration::from_secs(3)).expect("borrowing header wait was dropped");
                let mut response = start();
                response.extend(frame(0, 0, &message(b"native-duplex-response")));
                response.extend(headers(&[("grpc-status", "0")], true));
                socket.write_all(&response).unwrap();
                if !block_flush { duplex_peer_request_body(&mut socket); }
                let mut scratch = [0_u8; 1024];
                for _ in 0..32 {
                    if socket.read(&mut scratch).unwrap() == 0 { return; }
                }
                panic!("native client did not retire duplex transport");
            });
            let runtime = if multithread {
                RuntimeBuilder::new().worker_threads(2).build().unwrap()
            } else { RuntimeBuilder::current_thread().build().unwrap() };
            let complete = Arc::new(AtomicBool::new(false));
            let observed = Arc::clone(&complete);
            runtime.block_on(runtime.handle().spawn(async move {
                let cx = Cx::current().unwrap();
                let inner = TcpStream::connect_timeout(address, Duration::from_secs(3)).await.unwrap();
                let io = NativeDuplexIo {
                    inner, gate: Arc::clone(&gate), block_flush,
                    frame_remaining: CLIENT_PREFACE.len(), request_headers: false, headers_written: false,
                };
                let mut stream = NativeServerStream::new(&cx, io, "localhost", "/test.Service/Watch",
                    Request::new(Bytes::from_static(b"native-request")), IdentityCodec,
                    NativeStreamConfig { timeout: Some(Duration::from_secs(5)), ..NativeStreamConfig::default() }).unwrap();
                {
                    let mut wait = Box::pin(stream.headers());
                    poll_fn(|task| {
                        assert!(wait.as_mut().poll(task).is_pending(), "peer is gated until this wait is dropped");
                        if gate.parked.load(Ordering::SeqCst) { Poll::Ready(()) } else { Poll::Pending }
                    }).await;
                }
                assert!(!gate.open.load(Ordering::SeqCst));
                release_peer.try_send(()).expect("release native response after interrupted wait");
                stream.headers().await.unwrap();
                assert_eq!(stream.message().await.unwrap().unwrap().as_ref(), b"native-duplex-response");
                assert!(stream.message().await.unwrap().is_none());
                assert_eq!(stream.status().unwrap().code(), Code::Ok);
                assert!(gate.open.load(Ordering::SeqCst), "native read released the writer");
                assert_eq!(gate.drops.load(Ordering::SeqCst), 1);
                assert!(!cx.is_cancel_requested());
                complete.store(true, Ordering::Release);
            }));
            peer.join().expect("native duplex peer assertions");
            assert!(observed.load(Ordering::Acquire), "native duplex client assertions did not finish");
            assert!(observed_gate.parked.load(Ordering::SeqCst));
            assert_eq!(observed_gate.drops.load(Ordering::SeqCst), 1);
        }
    }
}
