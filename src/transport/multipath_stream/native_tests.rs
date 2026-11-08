//! Two real TCP peers contribute an object's authenticated symbol union.

use super::*;
use crate::Cx;
use crate::config::RaptorQConfig;
use crate::distributed::symbol_service::{SymbolBatchLimits, encode_symbol_batch};
use crate::error::ErrorKind;
use crate::net::TcpStream;
use crate::raptorq::{RaptorQReceiverBuilder, RaptorQSenderBuilder};
use crate::runtime::RuntimeBuilder;
use crate::transport::framed::{FramedSymbolStream, SymbolFrameLimits};
use crate::transport::sink::CollectingSink;
use crate::transport::stream::VecStream;
use crate::types::{Budget, ObjectParams};
use std::future::poll_fn;
use std::io::Write;
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
            assert!(!watchdog.signal.expired.load(Ordering::Acquire), "multipath symbol wall watchdog elapsed");
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
                assert!(Instant::now() < until, "multipath peer was never contacted");
                std::thread::park_timeout(Duration::from_millis(1));
            }
            Err(error) => panic!("multipath peer accept failed: {error}"),
        }
    }
}

fn wire(symbol: &AuthenticatedSymbol) -> Vec<u8> {
    let encoded = encode_symbol_batch(std::slice::from_ref(symbol), SymbolBatchLimits {
        max_encoded_bytes: 1024, max_symbols: 1, max_payload_bytes: 64, max_decoded_bytes: 1024,
    }).unwrap();
    let mut bytes = (encoded.as_ref().len() as u32).to_be_bytes().to_vec();
    bytes.extend_from_slice(encoded.as_ref());
    bytes
}

struct WitnessFailure<S> {
    source: S,
    signal: Option<mpsc::Sender<()>>,
}

impl<S: SymbolStream + Unpin> SymbolStream for WitnessFailure<S> {
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.source).poll_next(cx);
        if matches!(&result, Poll::Ready(Some(Err(_)))) {
            if let Some(signal) = this.signal.take() { let _ = signal.send(()); }
        }
        result
    }
}

#[test]
fn tcp_union_decodes_when_neither_peer_has_enough_symbols_and_one_fails_mid_frame() {
    let data: Vec<u8> = (0..512).map(|n| ((n * 29 + n / 5) % 251) as u8).collect();
    let object = ObjectId::new(7, 31);
    let mut config = RaptorQConfig::default();
    config.encoding.symbol_size = 64;
    config.encoding.max_block_size = 512;
    config.encoding.repair_overhead = 1.0;
    let mut sender = RaptorQSenderBuilder::new().config(config.clone())
        .security(SecurityContext::new(AuthKey::from_seed(42)))
        .transport(CollectingSink::new()).build().unwrap();
    let sent = sender.send_object(&Cx::for_testing(), object, &data).unwrap();
    assert_eq!(sent.source_symbols, 8);
    let symbols = sender.transport_mut().symbols().to_vec();
    let first: Vec<_> = symbols.iter().filter(|symbol| symbol.symbol().esi() < 4).cloned().collect();
    let second: Vec<_> = symbols.iter().filter(|symbol| symbol.symbol().esi() >= 3).cloned().collect();
    assert_eq!(first.len(), 4);
    assert_eq!(second.len(), 5);
    let params = ObjectParams::new(object, data.len() as u64, 64, 1, 8);
    for subset in [first.clone(), second.clone()] {
        let mut isolated = RaptorQReceiverBuilder::new().config(config.clone())
            .security(SecurityContext::new(AuthKey::from_seed(42)))
            .source(VecStream::new(subset)).build().unwrap();
        assert_eq!(isolated.receive_object(&Cx::for_testing(), &params).unwrap_err().kind(), ErrorKind::InsufficientSymbols,
            "neither individual peer can satisfy this object");
    }

    let (a_listener, a_address) = listener();
    let (b_listener, b_address) = listener();
    let (failure_seen, wait_failure) = mpsc::channel();
    let a_peer = std::thread::spawn(move || {
        let mut socket = accept(&a_listener);
        for symbol in &first { socket.write_all(&wire(symbol)).unwrap(); }
        // This peer disappears during its next frame. Its complete earlier
        // symbols must remain usable while the framing error retires this path.
        socket.write_all(&wire(&first[0])[..23]).unwrap();
        socket.flush().unwrap();
    });
    let b_peer = std::thread::spawn(move || {
        let mut socket = accept(&b_listener);
        for symbol in &second[..4] {
            for chunk in wire(symbol).chunks(7) { socket.write_all(chunk).unwrap(); }
        }
        socket.flush().unwrap();
        // Force the path failure to be observed before releasing the final
        // unique symbol; this does not rely on TCP coalescing or scheduling.
        wait_failure.recv_timeout(WATCHDOG).expect("first path failure must reach the receiver");
        socket.write_all(&wire(&second[4])).unwrap();
        socket.flush().unwrap();
    });

    run_native(|owner| async move {
        let first = TcpStream::connect(a_address).await.unwrap();
        let second = TcpStream::connect(b_address).await.unwrap();
        let frame_limits = SymbolFrameLimits::new(64).unwrap();
        let mut source = MultipathSymbolStream::new(AuthKey::from_seed(42), MultipathStreamLimits::new(2, 64, 1, 8).unwrap());
        source.add_path(PathId(1), WitnessFailure {
            source: FramedSymbolStream::new(first, AuthKey::from_seed(42), frame_limits),
            signal: Some(failure_seen),
        }).unwrap();
        source.add_path(PathId(2), FramedSymbolStream::new(second, AuthKey::from_seed(42), frame_limits)).unwrap();
        let mut receiver = RaptorQReceiverBuilder::new().config(config)
            .security(SecurityContext::new(AuthKey::from_seed(42))).source(source).build().unwrap();
        let decoded = {
            let mut session = receiver.start_receive_object(&owner, &params).unwrap();
            session.run().await.unwrap()
        };
        assert_eq!(decoded.data, data);
        assert_eq!(decoded.symbols_received, 8);
        assert!(decoded.all_symbols_verified());
        let source = receiver.source_mut();
        let first = source.path_stats(PathId(1)).unwrap();
        let second = source.path_stats(PathId(2)).unwrap();
        assert!(first.failed, "failure was observed before the last needed symbol");
        assert!(matches!(source.path_error(PathId(1)), Some(StreamError::Io { source }) if source.kind() == io::ErrorKind::UnexpectedEof));
        assert!(first.delivered_symbols > 0 && second.delivered_symbols > 0);
        assert_eq!(first.authenticated_symbols + second.authenticated_symbols, 9);
        assert_eq!(first.delivered_symbols + second.delivered_symbols, 8);
        assert_eq!(first.duplicate_symbols + second.duplicate_symbols, 1);
        assert_eq!(source.dedup_stats().duplicates_detected, 1);
        assert_eq!(source.dedup_stats().symbols_tracked, 8);
    });
    a_peer.join().unwrap();
    b_peer.join().unwrap();
}
