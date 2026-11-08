//! Actual TCP/TLS peers and the public asynchronous RaptorQ SDK composition.

use super::*;
use crate::Cx;
use crate::config::RaptorQConfig;
use crate::net::TcpStream;
use crate::raptorq::{RaptorQReceiverBuilder, RaptorQSenderBuilder};
use crate::runtime::RuntimeBuilder;
use crate::types::Budget;
use crate::types::symbol::ObjectParams;
use std::future::poll_fn;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const WATCHDOG: Duration = Duration::from_secs(10);

#[derive(Default)]
struct WatchdogSignal {
    expired: AtomicBool,
    waiter: Mutex<Option<Waker>>,
}

struct WallWatchdog {
    signal: Arc<WatchdogSignal>,
    stop: mpsc::Sender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl WallWatchdog {
    fn new() -> Self {
        let signal = Arc::new(WatchdogSignal::default());
        let expired = signal.clone();
        let (stop, stopping) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            if matches!(stopping.recv_timeout(WATCHDOG), Err(mpsc::RecvTimeoutError::Timeout)) {
                expired.expired.store(true, Ordering::Release);
                let waiter = expired.waiter.lock().unwrap().take();
                if let Some(waiter) = waiter { waiter.wake(); }
            }
        });
        Self { signal, stop, thread: Some(thread) }
    }
}

impl Drop for WallWatchdog {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
    }
}

fn run_native<F, Fut>(test: F)
where
    F: FnOnce(Cx) -> Fut,
    Fut: Future<Output = ()>,
{
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    let owner = runtime.request_cx_with_budget(Budget::INFINITE);
    let driver = runtime.request_cx_with_budget(Budget::INFINITE);
    let watchdog = WallWatchdog::new();
    runtime.block_on_with_cx(driver, Box::pin(async {
        let mut future = Box::pin(test(owner));
        poll_fn(|task| {
            *watchdog.signal.waiter.lock().unwrap() = Some(task.waker().clone());
            assert!(!watchdog.signal.expired.load(Ordering::Acquire), "symbol transport wall watchdog elapsed");
            future.as_mut().poll(task)
        }).await;
    }));
    drop(watchdog);
    assert!(runtime.shutdown_timeout(WATCHDOG));
}

fn listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    (listener, address)
}

fn accept(listener: &TcpListener) -> std::net::TcpStream {
    let until = Instant::now() + WATCHDOG;
    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                socket.set_nonblocking(false).unwrap();
                socket.set_read_timeout(Some(WATCHDOG)).unwrap();
                socket.set_write_timeout(Some(WATCHDOG)).unwrap();
                return socket;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < until, "native symbol peer was not contacted");
                std::thread::park_timeout(Duration::from_millis(1));
            }
            Err(error) => panic!("native symbol accept failed: {error}"),
        }
    }
}

fn peer_exchange(io: &mut (impl Read + Write)) {
    let limits = SymbolFrameLimits::new(128).unwrap();
    for expected in [symbol(0, b"first native symbol"), symbol(1, b"second native symbol")] {
        let mut prefix = [0u8; 4];
        io.read_exact(&mut prefix).unwrap();
        let length = u32::from_be_bytes(prefix) as usize;
        assert!(length + 4 <= limits.max_wire_bytes());
        let mut payload = vec![0; length];
        io.read_exact(&mut payload).unwrap();
        let decoded = decode_symbol_batch(&payload, &AuthKey::from_seed(42), limits.batch).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].symbol(), expected.symbol());
        assert!(decoded[0].is_verified());
    }
    let mut probe = [0u8; 1];
    assert_eq!(io.read(&mut probe).unwrap(), 0, "sender close completed after its last complete frame");
    // A peer can continue its response direction after the writer half closes.
    for fragment in wire(&[symbol(2, b"reply after half-close")]).chunks(3) {
        io.write_all(fragment).unwrap();
    }
    io.flush().unwrap();
}

async fn client_exchange<T: AsyncRead + AsyncWrite + Send + Unpin>(io: T) {
    let (read, write) = crate::io::split_owned(io);
    let limits = SymbolFrameLimits::new(128).unwrap();
    let mut sink = FramedSymbolSink::new(write, limits);
    let mut stream = FramedSymbolStream::new(read, AuthKey::from_seed(42), limits);
    sink.send(symbol(0, b"first native symbol")).await.unwrap();
    sink.send(symbol(1, b"second native symbol")).await.unwrap();
    sink.close().await.unwrap();
    let received = stream.next().await.unwrap().unwrap();
    assert_eq!(received.symbol(), symbol(2, b"reply after half-close").symbol());
    assert!(received.is_verified());
    assert!(stream.next().await.is_none());
}

#[test]
fn tcp_symbols_preserve_canonical_authentication_and_duplex_half_close() {
    let (listener, address) = listener();
    let peer = std::thread::spawn(move || {
        let mut socket = accept(&listener);
        peer_exchange(&mut socket);
    });
    run_native(|_| async move {
        client_exchange(TcpStream::connect(address).await.unwrap()).await;
    });
    peer.join().unwrap();
}

#[test]
fn asynchronous_raptorq_sdk_transfers_an_authenticated_object_over_tcp() {
    run_native(|cx| async move {
        let listener = crate::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut config = RaptorQConfig::default();
        config.encoding.symbol_size = 64;
        config.encoding.max_block_size = 4096;
        config.encoding.repair_overhead = 1.5;
        let limits = SymbolFrameLimits::new(64).unwrap();
        let data: Vec<u8> = (0..513).map(|n| ((n * 17) % 251) as u8).collect();
        let object = ObjectId::new(9, 12);
        let params = ObjectParams::new(object, data.len() as u64, 64, 1, 9);
        let sender_cx = cx.clone();
        let receiver_cx = cx.clone();
        let sender_config = config.clone();
        let sent_data = data.clone();
        let send = async move {
            let io = TcpStream::connect(address).await.unwrap();
            let mut sender = RaptorQSenderBuilder::new()
                .config(sender_config)
                .security(SecurityContext::new(AuthKey::from_seed(42)))
                .transport(FramedSymbolSink::new(io, limits))
                .build().unwrap();
            let outcome = {
                let mut session = sender.start_send_object(&sender_cx, object, &sent_data).unwrap();
                session.run().await.unwrap()
            };
            assert_eq!(outcome.source_symbols, 9);
            sender.transport_mut().close().await.unwrap();
            outcome
        };
        let receive = async move {
            let (io, _) = listener.accept().await.unwrap();
            let mut receiver = RaptorQReceiverBuilder::new()
                .config(config)
                .security(SecurityContext::new(AuthKey::from_seed(42)))
                .source(FramedSymbolStream::new(io, AuthKey::from_seed(42), limits))
                .build().unwrap();
            let outcome = {
                let mut session = receiver.start_receive_object(&receiver_cx, &params).unwrap();
                session.run().await.unwrap()
            };
            assert_eq!(outcome.data, data);
            assert!(outcome.all_symbols_verified());
            // Successful decoding can precede the sender's repair tail. Keep
            // the read owner alive until the sender flushes and half-closes.
            let mut remaining = 0;
            while let Some(symbol) = receiver.source_mut().next().await {
                assert!(symbol.unwrap().is_verified());
                remaining += 1;
            }
            (outcome, remaining)
        };
        let (sent, (received, remaining)) = futures_lite::future::zip(send, receive).await;
        assert_eq!(sent.symbols_sent, received.symbols_received + remaining);
        assert!(sent.repair_symbols > 0);
    });
}

#[cfg(feature = "tls")]
#[test]
fn authenticated_symbol_frames_work_over_verified_tls_and_owned_stream_halves() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    const CERT: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls/server.crt"));
    const KEY: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls/server.key"));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions().unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from_pem_slice(CERT).unwrap()], PrivateKeyDer::from_pem_slice(KEY).unwrap())
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from_pem_slice(CERT).unwrap()).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions().unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let (listener, address) = listener();
    let peer = std::thread::spawn(move || {
        let socket = accept(&listener);
        let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(Arc::new(server)).unwrap(), socket);
        peer_exchange(&mut tls);
        assert_eq!(tls.conn.server_name(), Some("localhost"));
        tls.conn.send_close_notify();
        tls.flush().unwrap();
    });
    run_native(|_| async move {
        let tcp = TcpStream::connect(address).await.unwrap();
        let tls = crate::tls::TlsConnector::new(client).connect("localhost", tcp).await.unwrap();
        client_exchange(tls).await;
    });
    peer.join().unwrap();
}
