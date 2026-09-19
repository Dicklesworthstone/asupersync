//! Public SymbolDistributor against actual TCP peers and runtime timers.
//! The tiny fixed-fixture protocol is TEST ONLY: signed symbols are verified,
//! but its acknowledgement is not authenticated and is not a production wire API.
#![cfg(all(feature = "test-internals", not(target_arch = "wasm32")))]

use asupersync::distributed::distribution::{
    DistributionConfig, DistributionResult, DistributorTransport, ReplicaAck, ReplicaFailure,
    SymbolDistributor,
};
use asupersync::distributed::encoding::EncodedState;
use asupersync::error::ErrorKind;
use asupersync::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use asupersync::net::TcpStream;
use asupersync::record::distributed_region::{ConsistencyLevel, ReplicaInfo};
use asupersync::runtime::{RuntimeBuilder, yield_now};
use asupersync::security::{AuthKey, AuthenticatedSymbol, AuthenticationTag, SecurityContext};
use asupersync::time::{timeout, wall_now};
use asupersync::types::{CancelKind, Time, symbol::{ObjectParams, Symbol}};
use asupersync::Cx;
use std::future::{Future, poll_fn};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::task::Poll;
use std::time::{Duration, Instant};

const SYMBOLS: usize = 4;
const PAYLOAD: usize = 16;
const KEY_SEED: u64 = 0xAD17_CAFE;
const WATCHDOG: Duration = Duration::from_secs(10);

fn encoded() -> EncodedState {
    EncodedState {
        params: ObjectParams::new_for_test(1, 1024),
        symbols: (0..SYMBOLS).map(|index| {
            Symbol::new_for_test(1, 0, index as u32, &[index as u8; PAYLOAD])
        }).collect(),
        source_count: 3,
        repair_count: 1,
        original_size: 48,
        encoded_at: Time::ZERO,
        layout_decision: Default::default(),
    }
}

fn native<T: Send + 'static>(workers: usize, future: impl Future<Output = T> + Send + 'static) -> T {
    let builder = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread().worker_threads(workers).with_sharded_state(true)
    };
    let runtime = builder.build().unwrap();
    let future: Pin<Box<dyn Future<Output = T> + Send>> = Box::pin(async move {
        timeout(wall_now(), WATCHDOG, future).await.expect("distribution outer watchdog")
    });
    let output = runtime.block_on(runtime.handle().spawn(future));
    let start = Instant::now();
    while !runtime.is_quiescent() {
        assert!(start.elapsed() < WATCHDOG, "owned native work did not drain");
        runtime.block_on(yield_now());
    }
    assert!(runtime.task_inspector(Default::default()).list_tasks().is_empty());
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(WATCHDOG));
    output
}

#[derive(Clone, Copy)]
enum Reply {
    Correct,
    Withheld,
    WrongIdentity,
    ShortCount,
}

#[derive(Debug)]
struct Receipt {
    symbols_verified: usize,
    ack_sent: bool,
    client_closed: bool,
}

struct Peer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<io::Result<Option<Receipt>>>>,
}

impl Peer {
    fn new(index: usize, reply: Reply, gate: usize, received: Arc<AtomicUsize>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            let start = Instant::now();
            let mut stream = loop {
                if stopped.load(Ordering::Acquire) { return Ok(None); }
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if start.elapsed() > WATCHDOG { return Err(io::ErrorKind::TimedOut.into()); }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => return Err(error),
                }
            };
            drop(listener);
            stream.set_read_timeout(Some(Duration::from_millis(100)))?;
            stream.set_write_timeout(Some(Duration::from_secs(2)))?;
            // Fixed small frame, independent of peer-supplied allocation lengths.
            // Keep the full receipt bounded even under timeout/cancellation.
            let mut wire = [0_u8; 4 + SYMBOLS * (PAYLOAD + 32)];
            let mut offset = 0;
            while offset < wire.len() {
                if stopped.load(Ordering::Acquire) || start.elapsed() > WATCHDOG {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                match stream.read(&mut wire[offset..]) {
                    Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                    Ok(count) => offset += count,
                    Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted) => {}
                    Err(error) => return Err(error),
                }
            }
            assert_eq!(u32::from_le_bytes(wire[..4].try_into().unwrap()) as usize, SYMBOLS);
            for (symbol_index, record) in wire[4..].chunks_exact(PAYLOAD + 32).enumerate() {
                let symbol = Symbol::new_for_test(1, 0, symbol_index as u32, &record[..PAYLOAD]);
                let tag = AuthenticationTag::from_bytes(record[PAYLOAD..].try_into().unwrap());
                assert_eq!(symbol.data(), &[symbol_index as u8; PAYLOAD]);
                assert!(tag.verify(&AuthKey::from_seed(KEY_SEED), &symbol));
            }
            received.fetch_or(1 << index, Ordering::AcqRel);
            while received.load(Ordering::Acquire) & gate != gate {
                if stopped.load(Ordering::Acquire) || start.elapsed() > WATCHDOG {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            let ack_sent = !matches!(reply, Reply::Withheld);
            if ack_sent {
                let id = if matches!(reply, Reply::WrongIdentity) { 99 } else { index as u8 };
                let count = if matches!(reply, Reply::ShortCount) { SYMBOLS - 1 } else { SYMBOLS };
                stream.write_all(&[id])?;
                stream.write_all(&(count as u32).to_le_bytes())?;
                stream.flush()?;
            }
            // Prove that the distributor retires the actual socket owner. No
            // acknowledgement/timeout alone counts as evidence of cleanup.
            let mut byte = [0];
            let closed = loop {
                match stream.read(&mut byte) {
                    Ok(0) => break true,
                    Ok(_) => return Err(io::ErrorKind::InvalidData.into()),
                    Err(error) if matches!(error.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted) => break true,
                    Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted) => {
                        if stopped.load(Ordering::Acquire) || start.elapsed() > WATCHDOG { break false; }
                    }
                    Err(error) => return Err(error),
                }
            };
            Ok(Some(Receipt { symbols_verified: SYMBOLS, ack_sent, client_closed: closed }))
        });
        Self { address, stop, worker: Some(worker) }
    }

    fn finish(mut self, expected_contact: bool, expected_ack: bool) {
        if !expected_contact { self.stop.store(true, Ordering::Release); }
        let receipt = self.worker.take().unwrap().join().unwrap().unwrap();
        if expected_contact {
            let receipt = receipt.expect("replica must have received the real batch");
            assert_eq!(receipt.symbols_verified, SYMBOLS);
            assert_eq!(receipt.ack_sent, expected_ack);
            assert!(receipt.client_closed, "client left its socket live after the result");
        } else {
            assert!(receipt.is_none(), "queued replica must not be contacted");
        }
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}

#[derive(Default)]
struct Counters {
    started: AtomicUsize,
    active: AtomicUsize,
    peak: AtomicUsize,
    parked: AtomicUsize,
}

struct SendOwner(Arc<Counters>);
impl SendOwner {
    fn new(counters: &Arc<Counters>) -> Self {
        counters.started.fetch_add(1, Ordering::SeqCst);
        let active = counters.active.fetch_add(1, Ordering::SeqCst) + 1;
        counters.peak.fetch_max(active, Ordering::SeqCst);
        Self(Arc::clone(counters))
    }
}
impl Drop for SendOwner {
    fn drop(&mut self) { self.0.active.fetch_sub(1, Ordering::SeqCst); }
}

struct TcpTransport {
    addresses: Vec<SocketAddr>,
    counters: Arc<Counters>,
}

impl DistributorTransport for TcpTransport {
    fn send_symbols(&self, replica_id: &str, symbols: Vec<AuthenticatedSymbol>)
        -> impl Future<Output = Result<ReplicaAck, ReplicaFailure>> + Send
    {
        let index: usize = replica_id[1..].parse().unwrap();
        let id = replica_id.to_owned();
        let address = self.addresses[index];
        let owner = SendOwner::new(&self.counters);
        let counters = Arc::clone(&self.counters);
        async move {
            let _owner = owner;
            let result = async {
                let mut socket = TcpStream::connect(address).await?;
                socket.write_all(&(symbols.len() as u32).to_le_bytes()).await?;
                for symbol in symbols {
                    assert_eq!(symbol.symbol().data().len(), PAYLOAD);
                    socket.write_all(symbol.symbol().data()).await?;
                    socket.write_all(symbol.tag().as_bytes()).await?;
                }
                socket.flush().await?;
                let mut wire = [0; 5];
                let mut offset = 0;
                while offset < wire.len() {
                    let count = poll_fn(|task| {
                        let mut buf = ReadBuf::new(&mut wire[offset..]);
                        match Pin::new(&mut socket).poll_read(task, &mut buf) {
                            Poll::Pending => {
                                counters.parked.fetch_or(1 << index, Ordering::Release);
                                Poll::Pending
                            }
                            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.filled().len())),
                            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                        }
                    }).await?;
                    if count == 0 { return Err(io::ErrorKind::UnexpectedEof.into()); }
                    offset += count;
                }
                Ok(ReplicaAck {
                    replica_id: format!("r{}", wire[0]),
                    symbols_received: u32::from_le_bytes(wire[1..].try_into().unwrap()),
                    ack_time: wall_now(),
                })
            }.await;
            result.map_err(|error: io::Error| ReplicaFailure {
                replica_id: id, error: error.to_string(), error_kind: ErrorKind::NodeUnavailable,
            })
        }
    }
}

fn setup(peers: &[Peer], counters: &Arc<Counters>) -> (Vec<ReplicaInfo>, SecurityContext, TcpTransport) {
    let replicas: Vec<_> = peers.iter().enumerate().map(|(i, p)| {
        ReplicaInfo::new(&format!("r{i}"), &p.address.to_string())
    }).collect();
    let security = SecurityContext::new(AuthKey::from_seed(KEY_SEED));
    for replica in &replicas { security.authorize_replica(&replica.id, None).unwrap(); }
    let transport = TcpTransport { addresses: peers.iter().map(|p| p.address).collect(), counters: Arc::clone(counters) };
    (replicas, security, transport)
}

async fn distribute(config: DistributionConfig, replicas: Vec<ReplicaInfo>, security: SecurityContext,
    transport: TcpTransport, context: Option<mpsc::Sender<Cx>>) -> DistributionResult
{
    let cx = Cx::current().expect("owned native task supplies its context");
    assert!(cx.timer_driver().is_some());
    if let Some(sender) = context { sender.send(cx.clone()).unwrap(); }
    let mut distributor = SymbolDistributor::new(config);
    let result = distributor.distribute(&cx, &encoded(), &replicas, &transport, &security).await;
    assert_eq!(transport.counters.active.load(Ordering::SeqCst), 0);
    assert_eq!(distributor.metrics.distributions_total, 1);
    assert_eq!(distributor.metrics.symbols_sent_total, u64::from(result.symbols_distributed));
    assert_eq!(distributor.metrics.acks_received_total, result.acks.len() as u64);
    result
}

#[test]
fn stalled_first_tcp_replica_does_not_starve_healthy_quorum_and_socket_is_retired() {
    for workers in [1, 2] {
        let received = Arc::new(AtomicUsize::new(0));
        let peers: Vec<_> = [Reply::Withheld, Reply::Correct, Reply::Correct].into_iter()
            .enumerate().map(|(i, reply)| Peer::new(i, reply, 0b111, Arc::clone(&received))).collect();
        let counters = Arc::new(Counters::default());
        let (replicas, security, transport) = setup(&peers, &counters);
        let result = native(workers, distribute(DistributionConfig {
            max_concurrent: 3, ack_timeout: Duration::from_secs(2), ..Default::default()
        }, replicas, security, transport, None));
        assert!(result.quorum_achieved);
        assert_eq!(result.acks.iter().map(|ack| ack.replica_id.as_str()).collect::<Vec<_>>(), ["r1", "r2"]);
        assert_eq!(result.failures.len(), 1);
        assert_eq!(result.failures[0].replica_id, "r0");
        assert_eq!(result.failures[0].error_kind, ErrorKind::DeadlineExceeded);
        assert_eq!(result.symbols_distributed, 12);
        assert_eq!(received.load(Ordering::Acquire), 0b111);
        assert!(counters.peak.load(Ordering::SeqCst) <= 3);
        for (i, peer) in peers.into_iter().enumerate() { peer.finish(true, i != 0); }
    }
}

#[test]
fn native_concurrency_limit_allows_pair_progress_without_over_admission() {
    let received = Arc::new(AtomicUsize::new(0));
    let peers: Vec<_> = (0..5).map(|i| Peer::new(i, Reply::Correct,
        if i < 2 { 0b11 } else if i < 4 { 0b1100 } else { 0b10000 }, Arc::clone(&received))).collect();
    let counters = Arc::new(Counters::default());
    let (replicas, security, transport) = setup(&peers, &counters);
    let result = native(2, distribute(DistributionConfig {
        consistency: ConsistencyLevel::All, max_concurrent: 2,
        ack_timeout: Duration::from_secs(2), ..Default::default()
    }, replicas, security, transport, None));
    assert!(result.quorum_achieved); assert_eq!(result.acks.len(), 5); assert!(result.failures.is_empty());
    assert_eq!(result.symbols_distributed, 20);
    assert_eq!(counters.started.load(Ordering::SeqCst), 5);
    assert_eq!(counters.peak.load(Ordering::SeqCst), 2);
    for peer in peers { peer.finish(true, true); }
}

#[test]
fn cancellation_from_another_thread_wakes_actual_parked_sends_and_keeps_queue_unstarted() {
    let received = Arc::new(AtomicUsize::new(0));
    let peers: Vec<_> = (0..4).map(|i| Peer::new(i, Reply::Withheld, 0, Arc::clone(&received))).collect();
    let counters = Arc::new(Counters::default());
    let (replicas, security, transport) = setup(&peers, &counters);
    let (sender, receiver) = mpsc::channel();
    let result = std::thread::scope(|scope| {
        let observed = Arc::clone(&counters);
        let canceller = scope.spawn(move || {
            let cx: Cx = receiver.recv_timeout(WATCHDOG).unwrap();
            let start = Instant::now();
            while observed.parked.load(Ordering::Acquire) & 0b11 != 0b11 {
                assert!(start.elapsed() < WATCHDOG, "two actual socket reads must park");
                std::thread::sleep(Duration::from_millis(1));
            }
            cx.cancel_fast(CancelKind::User);
        });
        let result = native(2, distribute(DistributionConfig {
            max_concurrent: 2, ack_timeout: Duration::from_secs(60), ..Default::default()
        }, replicas, security, transport, Some(sender)));
        canceller.join().unwrap();
        result
    });
    assert!(!result.quorum_achieved); assert!(result.acks.is_empty());
    assert_eq!(result.failures.len(), 4);
    assert!(result.failures.iter().all(|error| error.error_kind == ErrorKind::Cancelled));
    assert_eq!(result.symbols_distributed, 8);
    assert_eq!(counters.started.load(Ordering::SeqCst), 2);
    for (index, peer) in peers.into_iter().enumerate() { peer.finish(index < 2, false); }
}

#[test]
fn invalid_acknowledgements_over_tcp_do_not_contribute_votes() {
    let received = Arc::new(AtomicUsize::new(0));
    let peers: Vec<_> = [Reply::WrongIdentity, Reply::ShortCount, Reply::Correct].into_iter()
        .enumerate().map(|(i, reply)| Peer::new(i, reply, 0, Arc::clone(&received))).collect();
    let counters = Arc::new(Counters::default());
    let (replicas, security, transport) = setup(&peers, &counters);
    let result = native(2, distribute(DistributionConfig {
        max_concurrent: 3, ack_timeout: Duration::from_secs(2), ..Default::default()
    }, replicas, security, transport, None));
    assert!(!result.quorum_achieved); assert_eq!(result.acks.len(), 1);
    assert_eq!(result.acks[0].replica_id, "r2"); assert_eq!(result.failures.len(), 2);
    assert!(result.failures.iter().all(|error| error.error_kind == ErrorKind::ProtocolError));
    assert_eq!(result.failures[0].replica_id, "r0"); assert_eq!(result.failures[1].replica_id, "r1");
    for peer in peers { peer.finish(true, true); }
}
