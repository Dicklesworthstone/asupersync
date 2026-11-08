//! Real datagram boundaries, adversarial admission, and fountain-code recovery.

use super::{SymbolDatagramLimits, UdpSymbolSink, UdpSymbolStream};
use crate::Cx;
use crate::config::RaptorQConfig;
use crate::distributed::symbol_service::{
    SymbolBatchLimits, decode_symbol_batch, encode_symbol_batch,
};
use crate::error::ErrorKind;
use crate::net::UdpSocket;
use crate::raptorq::{RaptorQReceiverBuilder, RaptorQSenderBuilder};
use crate::runtime::RuntimeBuilder;
use crate::security::{AuthKey, AuthenticatedSymbol, AuthenticationTag, SecurityContext};
use crate::transport::sink::CollectingSink;
use crate::transport::{SinkError, StreamError, SymbolSinkExt, SymbolStream, SymbolStreamExt};
use crate::types::Budget;
use crate::types::symbol::{ObjectId, ObjectParams, Symbol, SymbolId, SymbolKind};
use std::future::{Future, poll_fn};
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

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
        let expiration = Arc::clone(&signal);
        let (stop, stopping) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            if matches!(
                stopping.recv_timeout(WATCHDOG),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                expiration.expired.store(true, Ordering::Release);
                let waiter = expiration.waiter.lock().unwrap().take();
                if let Some(waiter) = waiter {
                    waiter.wake();
                }
            }
        });
        Self {
            signal,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for WallWatchdog {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
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
    runtime.block_on_with_cx(
        driver,
        Box::pin(async {
            let mut future = Box::pin(test(owner));
            poll_fn(|task| {
                *watchdog.signal.waiter.lock().unwrap() = Some(task.waker().clone());
                assert!(
                    !watchdog.signal.expired.load(Ordering::Acquire),
                    "UDP symbol transport wall watchdog elapsed"
                );
                future.as_mut().poll(task)
            })
            .await;
        }),
    );
    drop(watchdog);
    assert!(runtime.shutdown_timeout(WATCHDOG));
}

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn socket() -> StdUdpSocket {
    let socket = StdUdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_read_timeout(Some(WATCHDOG)).unwrap();
    socket.set_write_timeout(Some(WATCHDOG)).unwrap();
    // The fairness test queues 34 tiny packets before its first receive.
    // Make that controlled burst independent of platform default socket sizes.
    socket2::SockRef::from(&socket)
        .set_recv_buffer_size(256 * 1024)
        .unwrap();
    socket
}

fn symbol(esi: u32, bytes: &[u8]) -> AuthenticatedSymbol {
    let symbol = Symbol::new(
        SymbolId::new(ObjectId::from_u128(17), 0, esi),
        bytes.to_vec(),
        SymbolKind::Source,
    );
    SecurityContext::new(AuthKey::from_seed(42)).sign_symbol(&symbol)
}

fn batch_limits() -> SymbolBatchLimits {
    SymbolBatchLimits {
        max_encoded_bytes: 65507,
        max_symbols: 1,
        max_payload_bytes: 65507,
        max_decoded_bytes: 65507 + std::mem::size_of::<AuthenticatedSymbol>(),
    }
}

fn wire(symbol: &AuthenticatedSymbol) -> Vec<u8> {
    encode_symbol_batch(std::slice::from_ref(symbol), batch_limits())
        .unwrap()
        .as_ref()
        .to_vec()
}

fn send_raw(peer: &StdUdpSocket, target: SocketAddr, packet: &[u8]) {
    assert_eq!(peer.send_to(packet, target).unwrap(), packet.len());
}

#[test]
fn datagram_limits_account_for_canonical_overhead_and_portable_udp_maximum() {
    assert!(SymbolDatagramLimits::new(0).is_err());
    assert!(SymbolDatagramLimits::new(usize::MAX).is_err());
    let maximum = SymbolDatagramLimits::new(65507 - 74).unwrap();
    assert_eq!(maximum.max_symbol_bytes(), 65507 - 74);
    assert_eq!(maximum.max_datagram_bytes(), 65507);
    assert!(SymbolDatagramLimits::new(65507 - 73).is_err());
    let defaults = SymbolDatagramLimits::default();
    assert_eq!(defaults.max_symbol_bytes(), 1024);
    assert_eq!(defaults.max_datagram_bytes(), 1024 + 74);
}

#[test]
fn a_different_connected_peer_is_rejected_before_an_endpoint_is_created() {
    run_native(|_| async {
        let actual = socket();
        let declared = socket();
        let actual_address = actual.local_addr().unwrap();
        let declared_address = declared.local_addr().unwrap();
        let sending = UdpSocket::from_std(socket()).unwrap();
        sending.connect(actual_address).await.unwrap();
        assert!(
            UdpSymbolSink::new(sending, declared_address, SymbolDatagramLimits::default()).is_err()
        );
        let receiving = UdpSocket::from_std(socket()).unwrap();
        receiving.connect(actual_address).await.unwrap();
        assert!(
            UdpSymbolStream::new(
                receiving,
                declared_address,
                AuthKey::from_seed(42),
                SymbolDatagramLimits::default(),
            )
            .is_err()
        );
    });
}

#[test]
fn native_send_has_canonical_wire_bytes_and_close_preserves_a_receive_clone() {
    let peer = socket();
    let peer_address = peer.local_addr().unwrap();
    let expected = symbol(7, b"hello");
    let peer_expected = expected.clone();
    let (closed, closing) = mpsc::channel();
    let responder = std::thread::spawn(move || {
        let mut packet = [0; 512];
        let (length, from) = peer.recv_from(&mut packet).unwrap();
        let packet = &packet[..length];
        // Independent byte-layout oracle: UDP carries the canonical batch
        // directly, without the stream adapter's four-byte length prefix.
        let mut golden = b"ASUPSYM\0".to_vec();
        golden.extend_from_slice(&1_u32.to_le_bytes());
        golden.extend_from_slice(&17_u128.to_le_bytes());
        golden.extend_from_slice(&1_u32.to_le_bytes());
        golden.push(0);
        golden.extend_from_slice(&7_u32.to_le_bytes());
        golden.push(0);
        golden.extend_from_slice(&5_u32.to_le_bytes());
        golden.extend_from_slice(peer_expected.tag().as_bytes());
        golden.extend_from_slice(b"hello");
        assert_eq!(packet, golden);
        let decoded = decode_symbol_batch(packet, &AuthKey::from_seed(42), batch_limits()).unwrap();
        assert_eq!(decoded[0].symbol(), peer_expected.symbol());
        assert!(decoded[0].is_verified());
        closing
            .recv_timeout(WATCHDOG)
            .expect("symbol sink closed before reply");
        send_raw(&peer, from, &wire(&symbol(8, b"reply")));
    });
    run_native(|_| async move {
        let socket = UdpSocket::from_std(socket()).unwrap();
        let read_socket = socket.try_clone().unwrap();
        let address = socket.local_addr().unwrap();
        let limits = SymbolDatagramLimits::new(5).unwrap();
        let mut sink = UdpSymbolSink::new(socket, peer_address, limits).unwrap();
        let mut stream =
            UdpSymbolStream::new(read_socket, peer_address, AuthKey::from_seed(42), limits).unwrap();
        assert_eq!(sink.peer_addr(), peer_address);
        assert_eq!(stream.peer_addr(), peer_address);
        assert_eq!(sink.local_addr().unwrap(), address);
        assert_eq!(stream.local_addr().unwrap(), address);
        let sentinel =
            AuthenticatedSymbol::from_parts(expected.symbol().clone(), AuthenticationTag::zero());
        assert!(matches!(
            sink.send(sentinel).await,
            Err(SinkError::SendFailed { .. })
        ));
        assert!(matches!(
            sink.send(symbol(9, b"oversized")).await,
            Err(SinkError::SendFailed { .. })
        ));
        assert_eq!(sink.datagrams_sent(), 0);
        sink.send(expected).await.unwrap();
        assert_eq!(sink.datagrams_sent(), 1);
        sink.flush().await.unwrap();
        sink.close().await.unwrap();
        closed.send(()).unwrap();
        assert!(matches!(
            sink.send(symbol(10, b"later")).await,
            Err(SinkError::Closed)
        ));
        assert_eq!(sink.datagrams_sent(), 1);
        let response = stream.next().await.unwrap().unwrap();
        assert_eq!(response.symbol().data(), b"reply");
        assert!(response.is_verified());
        assert_eq!(stream.stats().symbols_received, 1);
        assert_eq!(sink.into_socket().local_addr().unwrap(), address);
        assert_eq!(stream.into_socket().local_addr().unwrap(), address);
    });
    responder.join().unwrap();
}

#[test]
fn authentication_format_and_oversize_failures_are_packet_erasures_not_stream_eof() {
    run_native(|_| async {
        let peer = socket();
        let receiving = socket();
        let target = receiving.local_addr().unwrap();
        let good = symbol(0, b"hello");
        let valid = wire(&good);
        let wrong_key = SecurityContext::new(AuthKey::from_seed(7)).sign_symbol(good.symbol());
        let sentinel =
            AuthenticatedSymbol::from_parts(good.symbol().clone(), AuthenticationTag::zero());
        let mut tampered = valid.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let mut wrong_magic = valid.clone();
        wrong_magic[0] ^= 1;
        let mut oversized = valid.clone();
        oversized.extend_from_slice(b"garbage after a valid maximum-sized prefix");
        let invalid = [
            wire(&wrong_key),
            tampered,
            wire(&sentinel),
            Vec::new(),
            valid[..valid.len() - 1].to_vec(),
            wrong_magic,
            oversized,
        ];
        for packet in &invalid {
            send_raw(&peer, target, packet);
        }
        send_raw(&peer, target, &valid);
        let mut stream = UdpSymbolStream::new(
            UdpSocket::from_std(receiving).unwrap(),
            peer.local_addr().unwrap(),
            AuthKey::from_seed(42),
            SymbolDatagramLimits::new(5).unwrap(),
        )
        .unwrap();
        let received = stream.next().await.unwrap().unwrap();
        assert_eq!(received.symbol(), good.symbol());
        assert!(received.is_verified());
        let stats = stream.stats();
        assert_eq!(stats.rejected_authentication, 3);
        assert_eq!(
            stats.rejected_format, 3,
            "an empty datagram is malformed, never EOF"
        );
        assert_eq!(
            stats.rejected_oversize, 1,
            "truncation cannot authenticate a valid prefix"
        );
        assert_eq!(stats.rejected_peer, 0);
        assert_eq!(stats.symbols_received, 1);
        assert_eq!(stats.datagrams_received, 8);
        let mut task = Context::from_waker(Waker::noop());
        assert!(
            Pin::new(&mut stream).poll_next(&mut task).is_pending(),
            "UDP has no implicit EOF"
        );
    });
}

#[test]
fn an_authenticated_packet_from_an_unconfigured_peer_is_not_delivered() {
    run_native(|_| async {
        let peer = socket();
        let stranger = socket();
        let receiving = socket();
        let target = receiving.local_addr().unwrap();
        send_raw(&stranger, target, &wire(&symbol(9, b"wrong peer")));
        let mut stream = UdpSymbolStream::new(
            UdpSocket::from_std(receiving).unwrap(),
            peer.local_addr().unwrap(),
            AuthKey::from_seed(42),
            SymbolDatagramLimits::new(32).unwrap(),
        )
        .unwrap();
        let mut task = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut stream).poll_next(&mut task).is_pending());
        assert_eq!(stream.stats().rejected_peer, 1);
        assert_eq!(stream.stats().symbols_received, 0);
        send_raw(&peer, target, &wire(&symbol(1, b"right peer")));
        let received = stream.next().await.unwrap().unwrap();
        assert_eq!(received.symbol().esi(), 1);
        assert_eq!(received.symbol().data(), b"right peer");
    });
}

#[test]
fn invalid_datagram_flood_yields_after_thirty_two_packets() {
    run_native(|_| async {
        let peer = socket();
        let receiving = socket();
        let target = receiving.local_addr().unwrap();
        for _ in 0..33 {
            send_raw(&peer, target, &[]);
        }
        send_raw(&peer, target, &wire(&symbol(0, b"valid")));
        let mut stream = UdpSymbolStream::new(
            UdpSocket::from_std(receiving).unwrap(),
            peer.local_addr().unwrap(),
            AuthKey::from_seed(42),
            SymbolDatagramLimits::new(5).unwrap(),
        )
        .unwrap();
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&count));
        let mut task = Context::from_waker(&waker);
        assert!(Pin::new(&mut stream).poll_next(&mut task).is_pending());
        assert_eq!(stream.stats().datagrams_received, 32);
        assert_eq!(stream.stats().rejected_format, 32);
        assert_eq!(stream.stats().symbols_received, 0);
        assert_eq!(
            count.0.load(Ordering::SeqCst),
            1,
            "budget exhaustion schedules one continuation"
        );
        let received = match Pin::new(&mut stream).poll_next(&mut task) {
            Poll::Ready(Some(Ok(symbol))) => symbol,
            other => panic!("queued valid packet was not reached on the next bounded poll: {other:?}"),
        };
        assert_eq!(received.symbol().data(), b"valid");
        assert_eq!(stream.stats().datagrams_received, 34);
        assert_eq!(stream.stats().rejected_format, 33);
    });
}

#[test]
fn a_packet_arriving_after_poll_pending_wakes_the_native_receiver() {
    let peer = socket();
    let peer_address = peer.local_addr().unwrap();
    let receiving = socket();
    let target = receiving.local_addr().unwrap();
    let (start, started) = mpsc::channel();
    let producer = std::thread::spawn(move || {
        started
            .recv_timeout(WATCHDOG)
            .expect("receiver registered readiness");
        send_raw(&peer, target, &wire(&symbol(0, b"wake")));
    });
    run_native(|_| async move {
        let mut stream = UdpSymbolStream::new(
            UdpSocket::from_std(receiving).unwrap(),
            peer_address,
            AuthKey::from_seed(42),
            SymbolDatagramLimits::new(4).unwrap(),
        )
        .unwrap();
        let mut requested = false;
        let received = poll_fn(|task| {
            let result = Pin::new(&mut stream).poll_next(task);
            if result.is_pending() && !requested {
                requested = true;
                start.send(()).unwrap();
            }
            result
        })
        .await
        .unwrap()
        .unwrap();
        assert!(
            requested,
            "the source really parked before any datagram existed"
        );
        assert_eq!(received.symbol().data(), b"wake");
    });
    producer.join().unwrap();
}

#[test]
fn original_owner_cancellation_wakes_an_sdk_receive_parked_on_udp() {
    run_native(|owner| async move {
        let peer = socket();
        let mut config = RaptorQConfig::default();
        config.encoding.symbol_size = 64;
        config.encoding.max_block_size = 4096;
        let stream = UdpSymbolStream::new(
            UdpSocket::from_std(socket()).unwrap(),
            peer.local_addr().unwrap(),
            AuthKey::from_seed(42),
            SymbolDatagramLimits::new(64).unwrap(),
        )
        .unwrap();
        let mut receiver = RaptorQReceiverBuilder::new()
            .config(config)
            .security(SecurityContext::new(AuthKey::from_seed(42)))
            .source(stream)
            .build()
            .unwrap();
        let params = ObjectParams::new(ObjectId::from_u128(17), 64, 64, 1, 1);
        let mut session = receiver.start_receive_object(&owner, &params).unwrap();
        let counter = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&counter));
        let mut task = Context::from_waker(&waker);
        let mut waiting = Box::pin(session.run());
        assert!(waiting.as_mut().poll(&mut task).is_pending());
        assert_eq!(counter.0.load(Ordering::SeqCst), 0);
        owner.set_cancel_requested(true);
        assert!(
            counter.0.load(Ordering::SeqCst) > 0,
            "cancellation is independent of packet readiness"
        );
        match waiting.as_mut().poll(&mut task) {
            Poll::Ready(Err(error)) => assert_eq!(error.kind(), ErrorKind::Cancelled),
            other => panic!("cancelled UDP receive remained parked: {other:?}"),
        }
        drop(waiting);
        assert!(session.is_finished());
        assert_eq!(session.symbols_received(), 0);
    });
}

#[test]
fn a_socket_cancellation_error_is_reported_once_and_terminates_the_stream() {
    run_native(|owner| async move {
        let peer = socket();
        let receiving = socket();
        let target = receiving.local_addr().unwrap();
        let mut stream = UdpSymbolStream::new(
            UdpSocket::from_std(receiving).unwrap(),
            peer.local_addr().unwrap(),
            AuthKey::from_seed(42),
            SymbolDatagramLimits::new(5).unwrap(),
        )
        .unwrap();
        let mut task = Context::from_waker(Waker::noop());
        {
            let _ambient = owner.clone().set_current_restricted();
            owner.set_cancel_requested(true);
            assert!(matches!(
                Pin::new(&mut stream).poll_next(&mut task),
                Poll::Ready(Some(Err(StreamError::Cancelled)))
            ));
        }
        send_raw(&peer, target, &wire(&symbol(0, b"later")));
        assert!(matches!(
            Pin::new(&mut stream).poll_next(&mut task),
            Poll::Ready(None)
        ));
        assert_eq!(
            stream.stats().datagrams_received,
            0,
            "a terminal endpoint does not resume socket I/O"
        );
    });
}

#[test]
fn real_udp_reconstructs_after_deterministic_source_loss_reordering_and_duplicates() {
    run_native(|owner| async move {
        let mut config = RaptorQConfig::default();
        config.encoding.symbol_size = 64;
        config.encoding.max_block_size = 4096;
        config.encoding.repair_overhead = 2.0;
        let data: Vec<u8> = (0..513).map(|n| ((n * 17) % 251) as u8).collect();
        let object = ObjectId::from_u128(17);
        let auth = SecurityContext::new(AuthKey::from_seed(42));
        let mut fixture = RaptorQSenderBuilder::new()
            .config(config.clone())
            .security(auth.clone())
            .transport(CollectingSink::new())
            .build()
            .unwrap();
        let encoded = fixture.send_object(&owner, object, &data).unwrap();
        let symbols = fixture.transport_mut().symbols();
        let dropped = symbols
            .iter()
            .filter(|symbol| symbol.symbol().kind().is_source() && symbol.symbol().esi() < 2)
            .count();
        let mut transmitted: Vec<_> = symbols
            .iter()
            .filter(|symbol| !(symbol.symbol().kind().is_source() && symbol.symbol().esi() < 2))
            .cloned()
            .rev()
            .collect();
        assert_eq!(dropped, 2);
        assert!(encoded.repair_symbols > dropped);
        // Put two duplicate repair packets before enough unique symbols exist
        // to finish decoding, so the receive oracle must actually see them.
        let duplicate = transmitted[0].clone();
        transmitted.insert(0, duplicate.clone());
        transmitted.insert(0, duplicate);
        assert_eq!(transmitted.len(), encoded.symbols_sent);
        let receiving = socket();
        let sending = socket();
        let receiver_address = receiving.local_addr().unwrap();
        let sender_address = sending.local_addr().unwrap();
        let limits = SymbolDatagramLimits::new(64).unwrap();
        let sink =
            UdpSymbolSink::new(UdpSocket::from_std(sending).unwrap(), receiver_address, limits)
                .unwrap();
        let stream = UdpSymbolStream::new(
            UdpSocket::from_std(receiving).unwrap(),
            sender_address,
            AuthKey::from_seed(42),
            limits,
        )
        .unwrap();
        let mut sender = RaptorQSenderBuilder::new()
            .config(config.clone())
            .security(auth.clone())
            .transport(sink)
            .build()
            .unwrap();
        // Decode as soon as the retained equations suffice; the sender has
        // already chosen and transmitted a larger erasure margin.
        config.encoding.repair_overhead = 1.0;
        let mut receiver = RaptorQReceiverBuilder::new()
            .config(config)
            .security(auth)
            .source(stream)
            .build()
            .unwrap();
        let params = ObjectParams::new(
            object,
            data.len() as u64,
            64,
            1,
            encoded.source_symbols as u16,
        );
        let send = async {
            let mut session = sender.start_send_symbols(&owner, transmitted).unwrap();
            session.run().await.unwrap()
        };
        let receive = async {
            let mut session = receiver.start_receive_object(&owner, &params).unwrap();
            session.run().await.unwrap()
        };
        // Both endpoint owners outlive the concurrent operations. A receiver
        // finishing early cannot close its socket under the sender's repair tail.
        let (sent, received) = futures_lite::future::zip(send, receive).await;
        assert_eq!(sent, encoded.symbols_sent);
        assert_eq!(sender.transport_mut().datagrams_sent(), sent as u64);
        assert_eq!(received.data, data);
        assert!(received.all_symbols_verified());
        assert!(receiver.source_mut().stats().symbols_received > received.symbols_received as u64);
        assert_eq!(receiver.source_mut().stats().rejected_authentication, 0);
        sender.transport_mut().close().await.unwrap();
    });
}
