//! Public live-stream journeys over actual native TCP/TLS sockets.
//! The gated source cannot reach EOF until the peer has flushed its first epoch:
//! a whole-source spool implementation cannot pass that causal witness.

#![cfg(all(
    feature = "tls",
    feature = "test-internals",
    not(target_arch = "wasm32")
))]

use asupersync::Cx;
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use asupersync::net::atp::sdk::native_auth::live::{
    LIVE_STREAM_ALPN, LiveStreamConfig, LiveStreamError, LiveStreamReceiver, LiveStreamSender,
};
use asupersync::net::atp::sdk::{
    AtpSdk, NativeClientAuthorization, NativeClientCertificateId, NativeTlsIdentity, SessionConfig,
};
use asupersync::runtime::{JoinError, RuntimeBuilder, yield_now};
use asupersync::types::CancelReason;
use futures_lite::future::zip;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

mod live_reader {
    use super::*;
    use asupersync::net::atp::sdk::native_auth::live::LiveStreamReader;
    use std::future::poll_fn;

    struct CountedSource {
        data: &'static [u8],
        reads: Arc<AtomicUsize>,
    }
    impl AsyncRead for CountedSource {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let count = buffer.remaining().min(self.data.len());
            buffer.put_slice(&self.data[..count]);
            self.data = &self.data[count..];
            Poll::Ready(Ok(()))
        }
    }

    async fn buffered(cx: &Cx, reader: &LiveStreamReader, expected: usize) {
        asupersync::time::timeout(cx.now(), Duration::from_secs(5), async {
            while reader.buffered_bytes() != expected {
                yield_now().await;
            }
        })
        .await
        .expect("receiver must actually fill its bounded output pipe");
    }

    #[test]
    fn read_consumption_backpressures_the_live_peer_and_eof_requires_its_receipt() {
        for workers in [1, 2] {
            run(workers, async {
                let cx = Cx::current().unwrap();
                let scope = cx.scope();
                let send = sender(config(8, 100));
                let receive = receiver(config(8, 100));
                let listener = receive
                    .bind(&cx, "127.0.0.1:0".parse().unwrap())
                    .await
                    .unwrap();
                let address = listener.local_addr().unwrap();
                let mut reader = listener.open_reader(&cx, &scope).unwrap();
                assert_eq!(receive.active_streams(), 1);

                // A cancelled empty read owns no hidden bytes and cannot invent EOF.
                let mut first = [0; 4];
                poll_fn(|ctx| {
                    let mut buffer = ReadBuf::new(&mut first);
                    assert!(
                        Pin::new(&mut reader)
                            .poll_read(ctx, &mut buffer)
                            .is_pending()
                    );
                    assert!(buffer.filled().is_empty());
                    Poll::Ready(())
                })
                .await;

                let reads = Arc::new(AtomicUsize::new(0));
                let mut sending = send
                    .spawn_send_reader(
                        &cx,
                        &scope,
                        address,
                        CountedSource {
                            data: b"0123456789abcdef",
                            reads: Arc::clone(&reads),
                        },
                    )
                    .unwrap();
                buffered(&cx, &reader, 8).await;
                for _ in 0..32 {
                    yield_now().await;
                }
                assert_eq!(reads.load(Ordering::SeqCst), 1);
                assert_eq!(reader.buffer_capacity(), 8);
                assert_eq!(reader.received_bytes(), 8);
                assert_eq!(reader.consumed_bytes(), 0);
                assert!(reader.terminal().is_none());
                reader.read_exact(&mut first).await.unwrap();
                assert_eq!(&first, b"0123");
                assert_eq!(reader.buffered_bytes(), 4);
                for _ in 0..32 {
                    yield_now().await;
                }
                assert_eq!(reads.load(Ordering::SeqCst), 1);
                assert!(!sending.is_finished());

                let mut remaining = Vec::new();
                reader.read_to_end(&mut remaining).await.unwrap();
                assert_eq!(remaining, b"456789abcdef");
                assert_eq!((reader.received_bytes(), reader.consumed_bytes()), (16, 16));
                assert_eq!(reader.buffer_high_water(), 8);
                let receipt = reader
                    .terminal()
                    .expect("EOF requires a canonical join")
                    .as_ref()
                    .unwrap()
                    .outcome
                    .as_ref()
                    .unwrap()
                    .clone();
                assert_eq!(receipt, sending.join(&cx).await.unwrap().outcome.unwrap());
                assert_eq!(reader.read(&mut first).await.unwrap(), 0);
                assert_eq!(
                    reader
                        .wait_terminal()
                        .await
                        .as_ref()
                        .unwrap()
                        .outcome
                        .as_ref()
                        .unwrap(),
                    &receipt
                );
                assert_eq!((send.active_streams(), receive.active_streams()), (0, 0));
            });
        }
    }

    #[test]
    fn explicit_empty_finalization_returns_eof_and_retains_the_empty_receipt() {
        run(1, async {
            let cx = Cx::current().unwrap();
            let scope = cx.scope();
            let send = sender(config(8, 0));
            let receive = receiver(config(8, 0));
            let listener = receive
                .bind(&cx, "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let mut reader = listener.open_reader(&cx, &scope).unwrap();
            let mut output = Vec::new();
            let (sent, read) = zip(
                send.send_reader(&cx, address, b"".as_slice()),
                reader.read_to_end(&mut output),
            )
            .await;
            assert_eq!(read.unwrap(), 0);
            assert!(output.is_empty());
            let received = reader
                .terminal()
                .unwrap()
                .as_ref()
                .unwrap()
                .outcome
                .as_ref()
                .unwrap();
            assert_eq!(&sent.outcome.unwrap(), received);
            assert_eq!((received.prefix.bytes, received.prefix.epochs), (0, 0));
            assert_eq!(receive.active_streams(), 0);
        });
    }

    #[test]
    fn cancellation_drains_a_receiver_parked_on_an_unread_verified_epoch() {
        for workers in [1, 2] {
            run(workers, async {
                let cx = Cx::current().unwrap();
                let scope = cx.scope();
                let mut limits = config(8, 100);
                limits.operation_timeout = Duration::from_secs(3600);
                let send = sender(limits.clone());
                let receive = receiver(limits);
                let listener = receive
                    .bind(&cx, "127.0.0.1:0".parse().unwrap())
                    .await
                    .unwrap();
                let address = listener.local_addr().unwrap();
                let mut reader = listener.open_reader(&cx, &scope).unwrap();
                let reads = Arc::new(AtomicUsize::new(0));
                let mut sending = send
                    .spawn_send_reader(
                        &cx,
                        &scope,
                        address,
                        CountedSource {
                            data: b"0123456789abcdef",
                            reads: Arc::clone(&reads),
                        },
                    )
                    .unwrap();
                buffered(&cx, &reader, 8).await;
                for _ in 0..32 {
                    yield_now().await;
                }
                assert_eq!(reads.load(Ordering::SeqCst), 1);
                let reason = CancelReason::user("cancel live pull reader while epoch is unread");
                let report = asupersync::time::timeout(
                    cx.now(),
                    Duration::from_secs(5),
                    reader.cancel_and_wait(reason.clone()),
                )
                .await
                .expect("cancellation must wake the parked worker")
                .as_ref()
                .expect("cooperative receiver retains its domain result");
                assert!(
                    matches!(&report.outcome, Err(LiveStreamError::Cancelled(Some(actual))) if actual == &reason)
                );
                assert_eq!(report.sink_written_bytes, 8);
                assert_eq!(report.prefix.as_ref().unwrap().bytes, 0);
                assert_eq!(reader.buffered_bytes(), 0);
                assert_eq!(reader.consumed_bytes(), 0);
                assert_eq!(receive.active_streams(), 0);
                let mut bytes = [0; 8];
                let error = reader.read(&mut bytes).await.unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::Interrupted);
                let report = reader
                    .cancel_and_wait(CancelReason::user("repeat cancel"))
                    .await
                    .as_ref()
                    .unwrap();
                assert!(
                    matches!(&report.outcome, Err(LiveStreamError::Cancelled(Some(actual))) if actual == &reason)
                );
                let sent =
                    asupersync::time::timeout(cx.now(), Duration::from_secs(5), sending.join(&cx))
                        .await
                        .expect("receiver cancellation must close the peer connection")
                        .unwrap();
                assert!(sent.outcome.is_err());
                assert_eq!(send.active_streams(), 0);
            });
        }
    }

    #[test]
    fn dropping_a_full_reader_releases_the_real_listener_and_sender() {
        run(2, async {
            let cx = Cx::current().unwrap();
            let scope = cx.scope();
            let mut limits = config(8, 100);
            limits.operation_timeout = Duration::from_secs(3600);
            let send = sender(limits.clone());
            let receive = receiver(limits);
            let listener = receive
                .bind(&cx, "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let reader = listener.open_reader(&cx, &scope).unwrap();
            let mut sending = send
                .spawn_send_reader(
                    &cx,
                    &scope,
                    address,
                    CountedSource {
                        data: b"0123456789abcdef",
                        reads: Arc::new(AtomicUsize::new(0)),
                    },
                )
                .unwrap();
            buffered(&cx, &reader, 8).await;
            drop(reader);
            asupersync::time::timeout(cx.now(), Duration::from_secs(5), async {
                while receive.active_streams() != 0 {
                    yield_now().await;
                }
            })
            .await
            .expect("dropped reader worker must release its original admission");
            let sent =
                asupersync::time::timeout(cx.now(), Duration::from_secs(5), sending.join(&cx))
                    .await
                    .expect("dropped reader must close the peer connection")
                    .unwrap();
            assert!(sent.outcome.is_err());
            let replacement = receive
                .bind(&cx, "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            drop(replacement);
            assert_eq!((send.active_streams(), receive.active_streams()), (0, 0));
        });
    }

    #[test]
    fn authentication_failure_is_an_error_before_any_reader_bytes() {
        run(1, async {
            let cx = Cx::current().unwrap();
            let scope = cx.scope();
            let send = sender_with("localhost", "unlisted", config(8, 100));
            let receive = receiver(config(8, 100));
            let listener = receive
                .bind(&cx, "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let mut reader = listener.open_reader(&cx, &scope).unwrap();
            let mut bytes = Vec::new();
            let (sent, read) = zip(
                send.send_reader(&cx, address, b"forbidden".as_slice()),
                reader.read_to_end(&mut bytes),
            )
            .await;
            assert!(sent.outcome.is_err());
            assert!(read.is_err());
            assert!(bytes.is_empty());
            let received = reader.terminal().unwrap().as_ref().unwrap();
            assert!(matches!(received.outcome, Err(LiveStreamError::Tls(_))));
            assert!(received.prefix.is_none());
            assert_eq!(reader.received_bytes(), 0);
            assert_eq!(receive.active_streams(), 0);
        });
    }

    #[test]
    fn corrupt_epochs_raw_eof_and_invalid_final_commitments_never_become_reader_eof() {
        use asupersync::net::atp::protocol::frames::FrameType;
        for case in ["digest", "final", "eof"] {
            run(1, async move {
                let cx = Cx::current().unwrap();
                let scope = cx.scope();
                let receive = receiver(config(8, 100));
                let listener = receive
                    .bind(&cx, "127.0.0.1:0".parse().unwrap())
                    .await
                    .unwrap();
                let address = listener.local_addr().unwrap();
                let mut reader = listener.open_reader(&cx, &scope).unwrap();
                let peer = async {
                    let tcp = asupersync::net::TcpStream::connect(address).await.unwrap();
                    let connector = asupersync::tls::TlsConnector::new(raw_client_config());
                    let mut wire = RawWire::new(connector.connect("localhost", tcp).await.unwrap());
                    let mut hello = b"ATPLIVE1".to_vec();
                    hello.extend_from_slice(&[7; 32]);
                    hello.extend_from_slice(&8u32.to_be_bytes());
                    hello.extend_from_slice(&100u64.to_be_bytes());
                    wire.send(FrameType::Handshake, hello.clone()).await;
                    let ack = wire.receive().await;
                    assert_eq!(ack.frame_type(), FrameType::HandshakeAck);
                    assert_eq!(ack.payload(), hello);
                    if case == "eof" {
                        return;
                    }
                    let mut initial = Sha256::new();
                    initial.update(b"asupersync.atp.live.hello.v1");
                    initial.update(&hello);
                    let mut epoch = vec![0; 16];
                    epoch.extend_from_slice(&initial.finalize());
                    epoch.extend_from_slice(&Sha256::digest(b"verified"));
                    epoch.extend_from_slice(b"verified");
                    if case == "digest" {
                        epoch[87] ^= 1;
                    }
                    wire.send(FrameType::ObjectData, epoch).await;
                    if case == "final" {
                        // This acknowledgement cannot arrive until AsyncRead consumed the epoch.
                        let ack = wire.receive().await;
                        assert_eq!(ack.frame_type(), FrameType::Control);
                        let mut final_payload = ack.payload().to_vec();
                        final_payload.extend_from_slice(&[0; 32]);
                        wire.send(FrameType::ObjectComplete, final_payload).await;
                    }
                };
                let mut bytes = Vec::new();
                let (_, read) = zip(peer, reader.read_to_end(&mut bytes)).await;
                let error = read.expect_err("stream failure cannot be successful EOF");
                if case == "eof" {
                    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
                } else {
                    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                }
                assert_eq!(
                    bytes.as_slice(),
                    if case == "final" {
                        b"verified".as_slice()
                    } else {
                        b"".as_slice()
                    }
                );
                let report = reader.terminal().unwrap().as_ref().unwrap();
                assert!(report.outcome.is_err());
                assert_eq!(report.sink_written_bytes as usize, bytes.len());
                assert_eq!(reader.consumed_bytes() as usize, bytes.len());
                assert_eq!(receive.active_streams(), 0);
            });
        }
    }
}

mod live_writer {
    use super::*;
    use std::future::poll_fn;

    #[test]
    fn writable_live_prefix_arrives_before_finish_and_matches_the_reader_receipt() {
        for workers in [1, 2] {
            run(workers, async {
                let cx = Cx::current().unwrap();
                let scope = cx.scope();
                let send = sender(config(8, 100));
                let receive = receiver(config(8, 100));
                let listener = receive
                    .bind(&cx, "127.0.0.1:0".parse().unwrap())
                    .await
                    .unwrap();
                let address = listener.local_addr().unwrap();
                let mut reader = listener.open_reader(&cx, &scope).unwrap();
                let mut writer = send.open_writer(&cx, &scope, address).unwrap();
                writer.write_all(b"first").await.unwrap();
                let mut first = [0; 5];
                let (flushed, read) = zip(writer.flush(), reader.read_exact(&mut first)).await;
                flushed.unwrap();
                read.unwrap();
                assert_eq!(&first, b"first");
                assert_eq!(
                    (writer.accepted_bytes(), writer.acknowledged_bytes()),
                    (5, 5)
                );
                assert!(writer.terminal().is_none());
                assert!(reader.terminal().is_none());

                writer.write_all(b"-last").await.unwrap();
                let mut last = [0; 5];
                let (flushed, read) = zip(writer.flush(), reader.read_exact(&mut last)).await;
                flushed.unwrap();
                read.unwrap();
                assert_eq!(&last, b"-last");
                let mut trailing = Vec::new();
                let (sent, read) = zip(writer.finish(), reader.read_to_end(&mut trailing)).await;
                let sent = sent.as_ref().unwrap().outcome.as_ref().unwrap().clone();
                assert_eq!(read.unwrap(), 0);
                assert!(trailing.is_empty());
                let received = reader
                    .terminal()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .outcome
                    .as_ref()
                    .unwrap();
                assert_eq!(&sent, received);
                assert_eq!((sent.prefix.bytes, sent.prefix.epochs), (10, 2));
                let digest: [u8; 32] = Sha256::digest(b"first-last").into();
                assert_eq!(sent.source_sha256, digest);
                assert!(writer.buffer_high_water() <= writer.buffer_capacity());
                assert_eq!(
                    writer
                        .finish()
                        .await
                        .as_ref()
                        .unwrap()
                        .outcome
                        .as_ref()
                        .unwrap(),
                    &sent
                );
                assert_eq!(
                    writer.write(b"late").await.unwrap_err().kind(),
                    io::ErrorKind::BrokenPipe
                );
                assert_eq!((send.active_streams(), receive.active_streams()), (0, 0));
            });
        }
    }

    #[test]
    fn full_input_parks_writes_and_flush_waits_for_the_actual_remote_sink_barrier() {
        run(2, async {
            let cx = Cx::current().unwrap();
            let scope = cx.scope();
            let send = sender(config(8, 100));
            let receive = receiver(config(8, 100));
            let listener = receive
                .bind(&cx, "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let probe = Arc::new(Probe::default());
            let mut output = sink(&probe);
            output.gate_flush = true;
            let mut receiving = listener.spawn_receive_into(&cx, &scope, output).unwrap();
            let mut writer = send.open_writer(&cx, &scope, address).unwrap();
            writer.write_all(b"01234567").await.unwrap();
            witness(&cx, &probe.flush_parked).await;
            assert_eq!(
                writer.buffered_bytes(),
                0,
                "local consumption has already happened"
            );
            assert_eq!(
                writer.acknowledged_bytes(),
                0,
                "sink has not acknowledged the epoch"
            );
            poll_fn(|ctx| {
                assert!(Pin::new(&mut writer).poll_flush(ctx).is_pending());
                Poll::Ready(())
            })
            .await;

            // One more epoch fits locally while the first is in flight; a third cannot.
            writer.write_all(b"89abcdef").await.unwrap();
            assert_eq!(writer.buffered_bytes(), 8);
            poll_fn(|ctx| {
                assert!(
                    Pin::new(&mut writer)
                        .poll_write(ctx, b"not-admitted")
                        .is_pending()
                );
                Poll::Ready(())
            })
            .await;
            assert_eq!(writer.accepted_bytes(), 16);
            assert_eq!(writer.buffer_high_water(), 8);
            assert!(writer.terminal().is_none());
            probe.release_flush.store(true, Ordering::SeqCst);
            let wake = probe.flush_waiter.lock().unwrap().take();
            if let Some(wake) = wake {
                wake.wake();
            }
            writer.flush().await.unwrap();
            assert_eq!(writer.acknowledged_bytes(), 16);
            assert_eq!(*probe.bytes.lock().unwrap(), b"0123456789abcdef");
            let (sent, received) = zip(writer.finish(), receiving.join(&cx)).await;
            assert_eq!(
                sent.as_ref().unwrap().outcome.as_ref().unwrap(),
                &received.unwrap().outcome.unwrap(),
            );
            assert_eq!((send.active_streams(), receive.active_streams()), (0, 0));
        });
    }

    #[test]
    fn cancel_and_drop_wake_a_live_worker_waiting_for_more_producer_input() {
        for drop_writer in [false, true] {
            for workers in [1, 2] {
                run(workers, async move {
                    let cx = Cx::current().unwrap();
                    let scope = cx.scope();
                    let mut limits = config(8, 100);
                    limits.operation_timeout = Duration::from_secs(3600);
                    let send = sender(limits.clone());
                    let receive = receiver(limits);
                    let listener = receive
                        .bind(&cx, "127.0.0.1:0".parse().unwrap())
                        .await
                        .unwrap();
                    let address = listener.local_addr().unwrap();
                    let probe = Arc::new(Probe::default());
                    let mut receiving = listener
                        .spawn_receive_into(&cx, &scope, sink(&probe))
                        .unwrap();
                    let mut writer = send.open_writer(&cx, &scope, address).unwrap();
                    writer.write_all(b"first").await.unwrap();
                    writer.flush().await.unwrap();
                    for _ in 0..32 {
                        yield_now().await;
                    }
                    assert!(writer.terminal().is_none());
                    assert_eq!(writer.buffered_bytes(), 0);
                    assert_eq!(writer.acknowledged_bytes(), 5);
                    if drop_writer {
                        drop(writer);
                    } else {
                        let reason =
                            CancelReason::user("cancel live writer while producer is idle");
                        let report = asupersync::time::timeout(
                            cx.now(),
                            Duration::from_secs(5),
                            writer.cancel_and_wait(reason.clone()),
                        )
                        .await
                        .expect("cancel must wake the one-hour source read")
                        .as_ref()
                        .expect("cooperative sender must retain its domain report");
                        assert!(
                            matches!(&report.outcome, Err(LiveStreamError::Cancelled(Some(actual))) if actual == &reason)
                        );
                        assert_eq!(report.prefix.as_ref().unwrap().bytes, 5);
                        assert_eq!(writer.acknowledged_bytes(), 5);
                        let repeated = writer
                            .cancel_and_wait(CancelReason::user("repeat"))
                            .await
                            .as_ref()
                            .unwrap();
                        assert!(
                            matches!(&repeated.outcome, Err(LiveStreamError::Cancelled(Some(actual))) if actual == &reason)
                        );
                    }
                    let received = asupersync::time::timeout(
                        cx.now(),
                        Duration::from_secs(5),
                        receiving.join(&cx),
                    )
                    .await
                    .expect("abandoned input must close the connection, not fake source EOF")
                    .unwrap();
                    assert!(received.outcome.is_err());
                    assert_eq!(received.prefix.unwrap().bytes, 5);
                    assert_eq!(*probe.bytes.lock().unwrap(), b"first");
                    asupersync::time::timeout(cx.now(), Duration::from_secs(5), async {
                        while send.active_streams() != 0 {
                            yield_now().await;
                        }
                    })
                    .await
                    .expect("writer child must release its original admission");
                    assert_eq!(receive.active_streams(), 0);
                });
            }
        }
    }

    #[test]
    fn writer_capacity_precedes_enqueue_and_denied_work_cannot_admit_input() {
        run(1, async {
            let cx = Cx::current().unwrap();
            let scope = cx.scope();
            let send = sender(config(8, 100));
            let address = "127.0.0.1:9".parse().unwrap();
            let mut writer = send.open_writer(&cx, &scope, address).unwrap();
            assert_eq!(send.active_streams(), 1);
            assert!(matches!(
                send.clone().open_writer(&cx, &scope, address),
                Err(LiveStreamError::Capacity)
            ));
            // Before the current-thread scheduler polls the child, queued bytes
            // remain local and abort must retain task-level admission semantics.
            writer.write_all(b"queued").await.unwrap();
            let reason = CancelReason::user("cancel queued live writer");
            assert!(matches!(
                writer.cancel_and_wait(reason.clone()).await,
                Err(JoinError::Cancelled(actual)) if actual == &reason
            ));
            assert_eq!(writer.acknowledged_bytes(), 0);
            assert_eq!(writer.buffered_bytes(), 0);
            assert_eq!(send.active_streams(), 0);
            let denied = {
                let _restriction = Cx::push_restriction(asupersync::cx::cap::CapMask::none());
                Cx::current().unwrap()
            };
            assert!(matches!(
                send.open_writer(&denied, &scope, address),
                Err(LiveStreamError::MissingCapability)
            ));
            assert_eq!(send.active_streams(), 0);
        });
    }

    fn raw_server_config() -> rustls::ServerConfig {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots()),
            Arc::clone(&provider),
        )
        .build()
        .unwrap();
        let fixtures = fixtures();
        let key = fixtures["identities"]["server"]["key"].as_str().unwrap();
        let key = PrivateKeyDer::pem_reader_iter(&mut io::BufReader::new(key.as_bytes()))
            .next()
            .unwrap()
            .unwrap();
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![certificate("server")], key)
            .unwrap();
        config.alpn_protocols = vec![LIVE_STREAM_ALPN.to_vec()];
        config.send_tls13_tickets = 0;
        config
    }

    #[test]
    fn forged_epoch_acknowledgements_and_wrong_final_proofs_never_satisfy_writer_barriers() {
        use asupersync::net::atp::protocol::frames::FrameType;
        for wrong_ack in [false, true] {
            run(1, async move {
                let cx = Cx::current().unwrap();
                let scope = cx.scope();
                let listener = asupersync::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .unwrap();
                let address = listener.local_addr().unwrap();
                let send = sender(config(8, 100));
                let mut writer = send.open_writer(&cx, &scope, address).unwrap();
                writer.write_all(b"first").await.unwrap();
                let peer = async {
                    let acceptor = asupersync::tls::TlsAcceptor::new(raw_server_config());
                    let (tcp, _) = listener.accept().await.unwrap();
                    let mut wire = RawWire::new(acceptor.accept(tcp).await.unwrap());
                    let hello = wire.receive().await;
                    assert_eq!(hello.frame_type(), FrameType::Handshake);
                    wire.send(FrameType::HandshakeAck, hello.payload().to_vec())
                        .await;
                    let epoch = wire.receive().await;
                    assert_eq!(epoch.frame_type(), FrameType::ObjectData);
                    assert_eq!(&epoch.payload()[80..], b"first");
                    let mut chain = Sha256::new();
                    chain.update(b"asupersync.atp.live.epoch.v1");
                    chain.update(&epoch.payload()[16..48]);
                    chain.update(epoch.payload());
                    let mut ack = 1u64.to_be_bytes().to_vec();
                    ack.extend_from_slice(&5u64.to_be_bytes());
                    ack.extend_from_slice(&chain.finalize());
                    if wrong_ack {
                        ack[47] ^= 1;
                    }
                    wire.send(FrameType::Control, ack).await;
                    if !wrong_ack {
                        let final_frame = wire.receive().await;
                        assert_eq!(final_frame.frame_type(), FrameType::ObjectComplete);
                        let mut proof = final_frame.payload().to_vec();
                        proof[79] ^= 1;
                        wire.send(FrameType::Proof, proof).await;
                    }
                };
                let client = async {
                    let flushed = writer.flush().await;
                    if wrong_ack {
                        assert_eq!(flushed.unwrap_err().kind(), io::ErrorKind::InvalidData);
                        assert_eq!(writer.acknowledged_bytes(), 0);
                    } else {
                        flushed.unwrap();
                        assert_eq!(writer.acknowledged_bytes(), 5);
                        assert!(writer.terminal().is_none());
                    }
                    let report = writer.finish().await.as_ref().unwrap();
                    let expected = if wrong_ack {
                        "wrong epoch acknowledgement"
                    } else {
                        "wrong final proof"
                    };
                    assert!(
                        matches!(&report.outcome, Err(LiveStreamError::Protocol(actual)) if *actual == expected)
                    );
                    assert_eq!(
                        report.prefix.as_ref().unwrap().bytes,
                        if wrong_ack { 0 } else { 5 }
                    );
                };
                zip(peer, client).await;
                assert_eq!(send.active_streams(), 0);
            });
        }
    }
}

fn fixtures() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/atp_native_auth_identities.json")).unwrap()
}
fn certificate(name: &str) -> CertificateDer<'static> {
    let fixtures = fixtures();
    let text = if name == "ca" {
        fixtures["ca"].as_str()
    } else {
        fixtures["identities"][name]["certificate"].as_str()
    }
    .unwrap();
    CertificateDer::pem_reader_iter(&mut io::BufReader::new(text.as_bytes()))
        .next()
        .unwrap()
        .unwrap()
}
fn identity(name: &str) -> NativeTlsIdentity {
    let fixtures = fixtures();
    let text = fixtures["identities"][name]["key"].as_str().unwrap();
    let key = PrivateKeyDer::pem_reader_iter(&mut io::BufReader::new(text.as_bytes()))
        .next()
        .unwrap()
        .unwrap();
    NativeTlsIdentity::new(vec![certificate(name)], key).unwrap()
}
fn roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(certificate("ca")).unwrap();
    roots
}
fn sdk() -> AtpSdk {
    AtpSdk::new_in_process(SessionConfig {
        max_concurrent_transfers: 1,
        ..SessionConfig::default()
    })
}
fn config(epoch_bytes: usize, max_bytes: u64) -> LiveStreamConfig {
    let mut config = LiveStreamConfig::default();
    config.epoch_bytes = epoch_bytes;
    config.max_bytes = max_bytes;
    config.operation_timeout = Duration::from_secs(5);
    config
}
fn sender_with(name: &'static str, client: &str, config: LiveStreamConfig) -> LiveStreamSender {
    sdk()
        .live_stream_sender(
            config,
            ServerName::try_from(name).unwrap(),
            roots(),
            identity(client),
        )
        .unwrap()
}
fn sender(config: LiveStreamConfig) -> LiveStreamSender {
    sender_with("localhost", "allowed", config)
}
fn receiver(config: LiveStreamConfig) -> LiveStreamReceiver {
    let allowed = NativeClientCertificateId::from_certificate(&certificate("allowed"));
    let policy = NativeClientAuthorization::new(roots(), [allowed]).unwrap();
    sdk()
        .live_stream_receiver(config, identity("server"), policy)
        .unwrap()
}

fn run<T: Send + 'static>(workers: usize, future: impl Future<Output = T> + Send + 'static) -> T {
    let runtime = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::multi_thread()
            .worker_threads(workers)
            .with_sharded_state(true)
    }
    .build()
    .unwrap();
    let future: Pin<Box<dyn Future<Output = T> + Send>> = Box::pin(future);
    let result = runtime.block_on(runtime.handle().spawn(future));
    let started = Instant::now();
    // Observe quiescence outside block_on: its root is itself a live task.
    while !runtime.is_quiescent() {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "live children did not drain"
        );
        runtime.block_on(yield_now());
    }
    assert!(
        runtime
            .task_inspector(Default::default())
            .list_tasks()
            .is_empty()
    );
    assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    result
}
async fn witness(cx: &Cx, flag: &AtomicBool) {
    asupersync::time::timeout(cx.now(), Duration::from_secs(5), async {
        while !flag.load(Ordering::SeqCst) {
            yield_now().await;
        }
    })
    .await
    .expect("the test must reach its claimed live state");
}

#[derive(Default)]
struct Probe {
    bytes: Mutex<Vec<u8>>,
    first_flushed: AtomicBool,
    eof: AtomicBool,
    reads: AtomicUsize,
    source_waiter: Mutex<Option<Waker>>,
    flush_waiter: Mutex<Option<Waker>>,
    flush_parked: AtomicBool,
    release_flush: AtomicBool,
    source_parked: AtomicBool,
}
struct Sink {
    probe: Arc<Probe>,
    gate_flush: bool,
    fail_after: Option<usize>,
}
impl AsyncWrite for Sink {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut output = self.probe.bytes.lock().unwrap();
        let remaining = self
            .fail_after
            .unwrap_or(usize::MAX)
            .saturating_sub(output.len());
        if remaining == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "deliberate sink failure",
            )));
        }
        let count = bytes.len().min(remaining).min(3); // Exercise partial writes.
        output.extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.gate_flush && !self.probe.release_flush.load(Ordering::SeqCst) {
            let incoming = cx.waker().clone();
            let old = self.probe.flush_waiter.lock().unwrap().replace(incoming);
            drop(old);
            self.probe.flush_parked.store(true, Ordering::SeqCst);
            if !self.probe.release_flush.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
        }
        if self.probe.bytes.lock().unwrap().as_slice() == b"first" {
            assert!(
                !self.probe.eof.load(Ordering::SeqCst),
                "first prefix arrived only after EOF"
            );
            self.probe.first_flushed.store(true, Ordering::SeqCst);
            let wake = self.probe.source_waiter.lock().unwrap().take();
            if let Some(wake) = wake {
                wake.wake();
            }
        }
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("live receiver must not implicitly shut down a caller-owned sink");
    }
}
struct GatedSource {
    probe: Arc<Probe>,
    step: u8,
    park_forever: bool,
    fail: bool,
}
impl AsyncRead for GatedSource {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.step == 0 {
            buf.put_slice(b"first");
            self.step = 1;
            self.probe.reads.fetch_add(1, Ordering::SeqCst);
            return Poll::Ready(Ok(()));
        }
        if !self.probe.first_flushed.load(Ordering::SeqCst) {
            let incoming = cx.waker().clone();
            let old = self.probe.source_waiter.lock().unwrap().replace(incoming);
            drop(old);
            if !self.probe.first_flushed.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
        }
        if self.park_forever {
            self.probe.source_parked.store(true, Ordering::SeqCst);
            return Poll::Pending; // The production adapter must supply cancel/timeout wakes.
        }
        if self.fail {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "source failed after a prefix",
            )));
        }
        if self.step == 1 {
            buf.put_slice(b"-last");
            self.step = 2;
        } else {
            self.probe.eof.store(true, Ordering::SeqCst);
        }
        self.probe.reads.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
}
fn sink(probe: &Arc<Probe>) -> Sink {
    Sink {
        probe: Arc::clone(probe),
        gate_flush: false,
        fail_after: None,
    }
}
fn source(probe: &Arc<Probe>) -> GatedSource {
    GatedSource {
        probe: Arc::clone(probe),
        step: 0,
        park_forever: false,
        fail: false,
    }
}

#[test]
fn live_prefix_reaches_the_peer_before_producer_eof_on_both_native_backends() {
    for workers in [1, 2] {
        run(workers, async {
            let cx = Cx::current().unwrap();
            let scope = cx.scope();
            let send = sender(config(8, 100));
            let receive = receiver(config(8, 100));
            let listener = receive
                .bind(&cx, "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let probe = Arc::new(Probe::default());
            let mut receiving = listener
                .spawn_receive_into(&cx, &scope, sink(&probe))
                .unwrap();
            let mut sending = send
                .spawn_send_reader(&cx, &scope, address, source(&probe))
                .unwrap();
            let (sent, received) = zip(sending.join(&cx), receiving.join(&cx)).await;
            let sent = sent.unwrap();
            let received = received.unwrap();
            assert!(probe.first_flushed.load(Ordering::SeqCst));
            assert!(probe.eof.load(Ordering::SeqCst));
            assert_eq!(*probe.bytes.lock().unwrap(), b"first-last");
            assert_eq!(received.sink_written_bytes, 10);
            let sent = sent.outcome.unwrap();
            let received = received.outcome.unwrap();
            assert_eq!(sent, received);
            assert_eq!((sent.prefix.epochs, sent.prefix.bytes), (2, 10));
            let digest: [u8; 32] = Sha256::digest(b"first-last").into();
            assert_eq!(sent.source_sha256, digest);
            assert_eq!((send.active_streams(), receive.active_streams()), (0, 0));
        });
    }
}

#[test]
fn live_sink_backpressure_stops_source_read_ahead_at_one_epoch() {
    struct Counted {
        probe: Arc<Probe>,
        data: &'static [u8],
    }
    impl AsyncRead for Counted {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.probe.reads.fetch_add(1, Ordering::SeqCst);
            let count = self.data.len().min(buf.remaining());
            buf.put_slice(&self.data[..count]);
            self.data = &self.data[count..];
            Poll::Ready(Ok(()))
        }
    }
    run(2, async {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let send = sender(config(8, 100));
        let receive = receiver(config(8, 100));
        let listener = receive
            .bind(&cx, "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let probe = Arc::new(Probe::default());
        let mut output = sink(&probe);
        output.gate_flush = true;
        let mut receiving = listener.spawn_receive_into(&cx, &scope, output).unwrap();
        let input = Counted {
            probe: Arc::clone(&probe),
            data: b"0123456789abcdef",
        };
        let mut sending = send.spawn_send_reader(&cx, &scope, address, input).unwrap();
        witness(&cx, &probe.flush_parked).await;
        for _ in 0..64 {
            yield_now().await;
        }
        assert_eq!(
            probe.reads.load(Ordering::SeqCst),
            1,
            "unacknowledged sink flush cannot permit another read"
        );
        assert_eq!(probe.bytes.lock().unwrap().len(), 8);
        assert!(!sending.is_finished());
        probe.release_flush.store(true, Ordering::SeqCst);
        let wake = probe.flush_waiter.lock().unwrap().take();
        if let Some(wake) = wake {
            wake.wake();
        }
        let (sent, received) = zip(sending.join(&cx), receiving.join(&cx)).await;
        assert_eq!(
            sent.unwrap().outcome.unwrap(),
            received.unwrap().outcome.unwrap()
        );
        assert_eq!(*probe.bytes.lock().unwrap(), b"0123456789abcdef");
        assert_eq!((send.active_streams(), receive.active_streams()), (0, 0));
    });
}

#[test]
fn live_source_failure_is_not_successful_truncation() {
    run(1, async {
        let cx = Cx::current().unwrap();
        let send = sender(config(8, 100));
        let receive = receiver(config(8, 100));
        let listener = receive
            .bind(&cx, "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let probe = Arc::new(Probe::default());
        let mut input = source(&probe);
        input.fail = true;
        let mut output = sink(&probe);
        let (sent, received) = zip(
            send.send_reader(&cx, address, input),
            listener.receive_into(&cx, &mut output),
        )
        .await;
        assert!(
            matches!(sent.outcome, Err(LiveStreamError::Io(ref error)) if error.kind() == io::ErrorKind::InvalidData)
        );
        assert!(
            received.outcome.is_err(),
            "raw EOF must never finalize the prefix"
        );
        assert_eq!(sent.prefix.as_ref().unwrap().bytes, 5);
        assert_eq!(sent.prefix, received.prefix);
        assert_eq!(received.sink_written_bytes, 5);
        assert_eq!(*probe.bytes.lock().unwrap(), b"first");
        assert_eq!((send.active_streams(), receive.active_streams()), (0, 0));
    });
}

#[test]
fn live_partial_sink_failure_retains_written_bytes_but_does_not_ack_the_epoch() {
    run(1, async {
        let cx = Cx::current().unwrap();
        let send = sender(config(8, 100));
        let receive = receiver(config(8, 100));
        let listener = receive
            .bind(&cx, "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let probe = Arc::new(Probe::default());
        let mut output = sink(&probe);
        output.fail_after = Some(3);
        let (sent, received) = zip(
            send.send_reader(&cx, address, &b"abcdefgh"[..]),
            listener.receive_into(&cx, &mut output),
        )
        .await;
        assert!(
            matches!(received.outcome, Err(LiveStreamError::Io(ref error)) if error.kind() == io::ErrorKind::PermissionDenied)
        );
        assert!(sent.outcome.is_err());
        assert_eq!(received.sink_written_bytes, 3);
        assert_eq!(received.prefix.as_ref().unwrap().bytes, 0);
        assert_eq!(sent.prefix, received.prefix);
        assert_eq!(*probe.bytes.lock().unwrap(), b"abc");
        assert_eq!((send.active_streams(), receive.active_streams()), (0, 0));
    });
}

#[test]
fn live_cancel_wakes_a_parked_source_and_preserves_the_delivered_prefix() {
    for workers in [1, 2] {
        run(workers, async {
            let cx = Cx::current().unwrap();
            let scope = cx.scope();
            let mut sender_config = config(8, 100);
            sender_config.operation_timeout = Duration::from_secs(3600);
            let send = sender(sender_config);
            let receive = receiver(config(8, 100));
            let listener = receive
                .bind(&cx, "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let probe = Arc::new(Probe::default());
            let mut input = source(&probe);
            input.park_forever = true;
            let mut receiving = listener
                .spawn_receive_into(&cx, &scope, sink(&probe))
                .unwrap();
            let mut sending = send.spawn_send_reader(&cx, &scope, address, input).unwrap();
            witness(&cx, &probe.source_parked).await;
            assert!(probe.first_flushed.load(Ordering::SeqCst));
            let reason = CancelReason::user("cancel live source after confirmed first epoch");
            sending.abort_with_reason(reason.clone());
            let sent =
                asupersync::time::timeout(cx.now(), Duration::from_secs(5), sending.join(&cx))
                    .await
                    .expect("cancel wake must not wait for the one-hour source deadline")
                    .expect("acknowledged cancellation preserves the returned domain report");
            let received = receiving.join(&cx).await.unwrap();
            assert!(
                matches!(sent.outcome, Err(LiveStreamError::Cancelled(Some(ref actual))) if actual == &reason)
            );
            assert_eq!(sent.prefix.as_ref().unwrap().bytes, 5);
            assert_eq!(sent.prefix, received.prefix);
            assert!(received.outcome.is_err());
            assert_eq!(*probe.bytes.lock().unwrap(), b"first");
            assert_eq!((send.active_streams(), receive.active_streams()), (0, 0));
        });
    }
}

#[test]
fn live_negotiated_limits_and_empty_finalization_never_publish_an_oversized_epoch() {
    for (length, limit, success, prefix) in [
        (0, 0, true, 0),
        (1, 0, false, 0),
        (10, 10, true, 10),
        (11, 10, false, 9),
    ] {
        run(1, async move {
            let cx = Cx::current().unwrap();
            let send = sender(config(8, 100));
            let receive = receiver(config(3, limit));
            let listener = receive
                .bind(&cx, "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let input = vec![9; length];
            let mut output = Vec::new();
            let (sent, received) = zip(
                send.send_reader(&cx, address, input.as_slice()),
                listener.receive_into(&cx, &mut output),
            )
            .await;
            assert_eq!(output, vec![9; prefix]);
            assert_eq!(received.sink_written_bytes, prefix as u64);
            assert_eq!(sent.prefix, received.prefix);
            if success {
                let sent = sent.outcome.unwrap();
                let received = received.outcome.unwrap();
                assert_eq!(sent, received);
                let hash: [u8; 32] = Sha256::digest(&input).into();
                assert_eq!(sent.source_sha256, hash);
                assert_eq!(sent.prefix.bytes, length as u64);
            } else {
                assert!(
                    matches!(sent.outcome, Err(LiveStreamError::TooLarge(actual)) if actual == limit)
                );
                assert!(received.outcome.is_err());
            }
            assert_eq!((send.active_streams(), receive.active_streams()), (0, 0));
        });
    }
}

#[test]
fn live_authentication_failure_cannot_poll_a_source_or_touch_a_sink() {
    for (name, client) in [("localhost", "unlisted"), ("wrong.example", "allowed")] {
        run(1, async move {
            let cx = Cx::current().unwrap();
            let send = sender_with(name, client, config(8, 100));
            let receive = receiver(config(8, 100));
            let listener = receive
                .bind(&cx, "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let probe = Arc::new(Probe::default());
            let mut output = sink(&probe);
            let (sent, received) = zip(
                send.send_reader(&cx, address, source(&probe)),
                listener.receive_into(&cx, &mut output),
            )
            .await;
            assert!(sent.outcome.is_err() && received.outcome.is_err());
            assert!(
                matches!(sent.outcome, Err(LiveStreamError::Tls(_)))
                    || matches!(received.outcome, Err(LiveStreamError::Tls(_))),
                "certificate refusal must reach TLS, not pass via arbitrary timeout"
            );
            assert_eq!(probe.reads.load(Ordering::SeqCst), 0);
            assert!(probe.bytes.lock().unwrap().is_empty());
            assert!(sent.prefix.is_none() && received.prefix.is_none());
            assert_eq!((send.active_streams(), receive.active_streams()), (0, 0));
        });
    }
}

#[test]
fn live_capacity_is_reserved_before_enqueue_and_rejected_work_has_no_io() {
    run(1, async {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let send = sender(config(8, 100));
        let receive = receiver(config(8, 100));
        let probe = Arc::new(Probe::default());
        let address = "127.0.0.1:9".parse().unwrap();
        let mut first = send
            .spawn_send_reader(&cx, &scope, address, source(&probe))
            .unwrap();
        assert_eq!(send.active_streams(), 1);
        assert!(matches!(
            send.clone()
                .spawn_send_reader(&cx, &scope, address, source(&probe)),
            Err(LiveStreamError::Capacity)
        ));
        first.abort_with_reason(CancelReason::user("cancel queued live stream"));
        assert!(matches!(
            first.join(&cx).await,
            Err(JoinError::Cancelled(_))
        ));
        assert_eq!(probe.reads.load(Ordering::SeqCst), 0);
        assert_eq!(send.active_streams(), 0);
        // Capability denial is a runtime attenuation of a full-capability Cx,
        // not a compile-time no-cap context: capture the restriction into a
        // Cx<All> and release the thread-local guard before the await.
        let denied = {
            let _restriction = Cx::push_restriction(asupersync::cx::cap::CapMask::none());
            Cx::current().expect("native runtime installs a context")
        };
        let missing = send.send_reader(&denied, address, source(&probe)).await;
        assert!(matches!(
            missing.outcome,
            Err(LiveStreamError::MissingCapability)
        ));
        let listener = receive
            .bind(&cx, "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let bound = listener.local_addr().unwrap();
        assert!(matches!(
            receive
                .clone()
                .bind(&cx, "127.0.0.1:0".parse().unwrap())
                .await,
            Err(LiveStreamError::Capacity)
        ));
        drop(listener);
        assert_eq!(receive.active_streams(), 0);
        let _rebound = std::net::TcpListener::bind(bound)
            .expect("dropped listener releases its actual socket");
    });
}

// Independently driven authenticated peers test the wire boundary, not just
// production encode/decode helpers agreeing with each other in memory.
struct RawWire {
    stream: asupersync::tls::TlsStream<asupersync::net::TcpStream>,
    codec: asupersync::net::atp::protocol::codec::AtpFrameCodec,
    bytes: asupersync::bytes::BytesMut,
}
impl RawWire {
    fn new(stream: asupersync::tls::TlsStream<asupersync::net::TcpStream>) -> Self {
        assert_eq!(stream.alpn_protocol(), Some(LIVE_STREAM_ALPN));
        Self {
            stream,
            codec: asupersync::net::atp::protocol::codec::AtpFrameCodec::new(),
            bytes: asupersync::bytes::BytesMut::new(),
        }
    }
    async fn send(
        &mut self,
        kind: asupersync::net::atp::protocol::frames::FrameType,
        payload: Vec<u8>,
    ) {
        use asupersync::net::atp::protocol::frames::{Frame, ProtocolVersion};
        self.stream
            .write_all(
                &Frame::new(ProtocolVersion::V0, kind, payload)
                    .unwrap()
                    .to_wire_bytes()
                    .unwrap(),
            )
            .await
            .unwrap();
        self.stream.flush().await.unwrap();
    }
    async fn receive(&mut self) -> asupersync::net::atp::protocol::frames::Frame {
        use asupersync::codec::Decoder;
        loop {
            if let Some(frame) = self.codec.decode(&mut self.bytes).unwrap() {
                return frame;
            }
            let mut bytes = [0; 4096];
            let count = self.stream.read(&mut bytes).await.unwrap();
            assert!(count > 0, "required peer frame is missing");
            self.bytes.extend_from_slice(&bytes[..count]);
        }
    }
}
fn raw_client_config() -> rustls::ClientConfig {
    let fixtures = fixtures();
    let key = fixtures["identities"]["allowed"]["key"].as_str().unwrap();
    let key = PrivateKeyDer::pem_reader_iter(&mut io::BufReader::new(key.as_bytes()))
        .next()
        .unwrap()
        .unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots())
    .with_client_auth_cert(vec![certificate("allowed")], key)
    .unwrap();
    config.alpn_protocols = vec![LIVE_STREAM_ALPN.to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    config
}

#[test]
fn live_authenticated_malformed_epochs_never_escape_integrity_or_finalization_checks() {
    use asupersync::net::atp::protocol::frames::{Frame, FrameType, ProtocolVersion};
    for (case, expected_bytes) in [
        ("digest", 0),
        ("sequence", 0),
        ("replay", 8),
        ("final", 8),
        ("truncated", 0),
        ("eof", 0),
        ("oversize", 0),
    ] {
        run(1, async move {
            let cx = Cx::current().unwrap();
            let receive = receiver(config(8, 100));
            let listener = receive
                .bind(&cx, "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let peer = async {
                let tcp = asupersync::net::TcpStream::connect(address).await.unwrap();
                let connector = asupersync::tls::TlsConnector::new(raw_client_config());
                let mut wire = RawWire::new(connector.connect("localhost", tcp).await.unwrap());
                let mut hello = b"ATPLIVE1".to_vec();
                hello.extend_from_slice(&[7; 32]);
                hello.extend_from_slice(&8u32.to_be_bytes());
                hello.extend_from_slice(&100u64.to_be_bytes());
                wire.send(FrameType::Handshake, hello.clone()).await;
                let ack = wire.receive().await;
                assert_eq!(ack.frame_type(), FrameType::HandshakeAck);
                assert_eq!(ack.payload(), hello);
                let mut initial = Sha256::new();
                initial.update(b"asupersync.atp.live.hello.v1");
                initial.update(&hello);
                let mut epoch = vec![0; 16];
                epoch.extend_from_slice(&initial.finalize());
                epoch.extend_from_slice(&Sha256::digest(b"verified"));
                epoch.extend_from_slice(b"verified");
                if case == "eof" {
                    return;
                } // Even an empty stream needs finalization.
                if case == "replay" || case == "final" {
                    wire.send(FrameType::ObjectData, epoch.clone()).await;
                    let ack = wire.receive().await;
                    assert_eq!(ack.frame_type(), FrameType::Control);
                    assert_eq!(
                        u64::from_be_bytes(ack.payload()[8..16].try_into().unwrap()),
                        8
                    );
                    if case == "final" {
                        let mut final_payload = ack.payload().to_vec();
                        final_payload.extend_from_slice(&[0; 32]);
                        wire.send(FrameType::ObjectComplete, final_payload).await;
                        return;
                    }
                }
                if case == "digest" {
                    epoch[87] ^= 1;
                }
                if case == "sequence" {
                    epoch[7] = 1;
                }
                if case == "oversize" {
                    epoch = vec![0; 64 * 1024 + 257];
                }
                let mut bytes = Frame::new(ProtocolVersion::V0, FrameType::ObjectData, epoch)
                    .unwrap()
                    .to_wire_bytes()
                    .unwrap();
                if case == "truncated" {
                    bytes.pop();
                }
                // Rejection may close the socket before an oversized frame finishes.
                let _ = wire.stream.write_all(&bytes).await;
                let _ = wire.stream.flush().await;
            };
            let mut output = Vec::new();
            let (_, report) = zip(peer, listener.receive_into(&cx, &mut output)).await;
            match case {
                "digest" => assert!(matches!(
                    report.outcome,
                    Err(LiveStreamError::Protocol("epoch digest mismatch"))
                )),
                "sequence" | "replay" => assert!(matches!(
                    report.outcome,
                    Err(LiveStreamError::Protocol("noncontiguous or rebound epoch"))
                )),
                "final" => assert!(matches!(
                    report.outcome,
                    Err(LiveStreamError::Protocol("wrong final stream commitment"))
                )),
                "oversize" => assert!(matches!(report.outcome, Err(LiveStreamError::Frame(_)))),
                _ => assert!(
                    matches!(report.outcome, Err(LiveStreamError::Io(ref error)) if error.kind() == io::ErrorKind::UnexpectedEof)
                ),
            }
            assert_eq!(output.len(), expected_bytes);
            if expected_bytes > 0 {
                assert_eq!(output, b"verified");
            }
            assert_eq!(report.sink_written_bytes, expected_bytes as u64);
            assert_eq!(report.prefix.unwrap().bytes, expected_bytes as u64);
            assert_eq!(receive.active_streams(), 0);
        });
    }
}

#[test]
fn live_sender_requires_the_exact_final_proof_even_for_an_empty_source() {
    use asupersync::net::atp::protocol::frames::FrameType;
    run(1, async {
        let cx = Cx::current().unwrap();
        let listener = asupersync::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let peer = async {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots()),
                Arc::clone(&provider),
            )
            .build()
            .unwrap();
            let fixtures = fixtures();
            let key = fixtures["identities"]["server"]["key"].as_str().unwrap();
            let key = PrivateKeyDer::pem_reader_iter(&mut io::BufReader::new(key.as_bytes()))
                .next()
                .unwrap()
                .unwrap();
            let mut config = rustls::ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_client_cert_verifier(verifier)
                .with_single_cert(vec![certificate("server")], key)
                .unwrap();
            config.alpn_protocols = vec![LIVE_STREAM_ALPN.to_vec()];
            config.send_tls13_tickets = 0;
            let acceptor = asupersync::tls::TlsAcceptor::new(config);
            let (tcp, _) = listener.accept().await.unwrap();
            let mut wire = RawWire::new(acceptor.accept(tcp).await.unwrap());
            let hello = wire.receive().await;
            assert_eq!(hello.frame_type(), FrameType::Handshake);
            wire.send(FrameType::HandshakeAck, hello.payload().to_vec())
                .await;
            let final_frame = wire.receive().await;
            assert_eq!(final_frame.frame_type(), FrameType::ObjectComplete);
            assert_eq!(final_frame.payload().len(), 80);
            let mut wrong = final_frame.payload().to_vec();
            wrong[79] ^= 1;
            wire.send(FrameType::Proof, wrong).await;
        };
        let send = sender(config(8, 100));
        let (report, ()) = zip(send.send_reader(&cx, address, &b""[..]), peer).await;
        assert!(matches!(
            report.outcome,
            Err(LiveStreamError::Protocol("wrong final proof"))
        ));
        assert_eq!(report.prefix.unwrap().bytes, 0);
        assert_eq!(send.active_streams(), 0);
    });
}

#[test]
fn live_stalled_sources_and_sinks_have_real_timeout_wakeups() {
    for stall_source in [true, false] {
        run(1, async move {
            let cx = Cx::current().unwrap();
            let scope = cx.scope();
            let mut send_config = config(8, 100);
            let mut receive_config = config(8, 100);
            if stall_source {
                send_config.operation_timeout = Duration::from_secs(1);
            } else {
                receive_config.operation_timeout = Duration::from_secs(1);
            }
            let send = sender(send_config);
            let receive = receiver(receive_config);
            let listener = receive
                .bind(&cx, "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let probe = Arc::new(Probe::default());
            let mut input = source(&probe);
            input.park_forever = stall_source;
            let mut output = sink(&probe);
            output.gate_flush = !stall_source;
            let mut receiving = listener.spawn_receive_into(&cx, &scope, output).unwrap();
            let mut sending = send.spawn_send_reader(&cx, &scope, address, input).unwrap();
            witness(
                &cx,
                if stall_source {
                    &probe.source_parked
                } else {
                    &probe.flush_parked
                },
            )
            .await;
            let (sent, received) = zip(sending.join(&cx), receiving.join(&cx)).await;
            let sent = sent.unwrap();
            let received = received.unwrap();
            if stall_source {
                assert!(matches!(
                    sent.outcome,
                    Err(LiveStreamError::Timeout("source read"))
                ));
                assert!(received.outcome.is_err());
                assert_eq!(sent.prefix.as_ref().unwrap().bytes, 5);
                assert_eq!(sent.prefix, received.prefix);
            } else {
                assert!(matches!(
                    received.outcome,
                    Err(LiveStreamError::Timeout("sink epoch"))
                ));
                assert!(sent.outcome.is_err());
                assert_eq!(received.sink_written_bytes, 5);
                assert_eq!(received.prefix.as_ref().unwrap().bytes, 0);
            }
            assert_eq!((send.active_streams(), receive.active_streams()), (0, 0));
        });
    }
}
