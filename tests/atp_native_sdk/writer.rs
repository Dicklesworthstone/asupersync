//! Writable native uploads: real transport and independently checked file bytes.

use super::{assert_content, fixture, native_client, receiver_config, run_native, sender_config};
use asupersync::Cx;
use asupersync::io::{AsyncWrite, AsyncWriteExt};
use asupersync::net::atp::sdk::native::upload::NativeUploadWriterTerminal;
use asupersync::net::atp::sdk::native::{NativeTransferError, NativeUploadError, NativeUploadOptions};
use asupersync::net::atp::transport_quic::QuicReceiveOptions;
use asupersync::runtime::JoinError;
use asupersync::types::CancelReason;
use futures_lite::future::zip;
use sha2::{Digest, Sha256};
use std::future::Future;
use std::io;
use std::net::UdpSocket;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

fn assert_clean(parent: &Path) {
    assert_eq!(std::fs::read_dir(parent).unwrap().count(), 1);
    assert_eq!(std::fs::read(parent.join("keep.txt")).unwrap(), b"untouched");
}

fn assert_cancelled(result: &NativeUploadWriterTerminal, reason: &CancelReason) {
    match result {
        Err(JoinError::Cancelled(actual)) => assert_eq!(actual, reason),
        Ok(report) => {
            assert!(matches!(&report.outcome,
                Err(NativeUploadError::Cancelled { reason: Some(actual) }) if actual == reason),
                "unexpected report: {report:?}");
            assert!(report.cleanup_error.is_none());
        }
        other => panic!("unexpected cancellation result: {other:?}"),
    }
}

#[test]
fn native_writer_delivers_exact_bytes_and_shutdown_waits_for_the_peer() {
    for (workers, length) in [(1, 128 * 1024 + 17), (2, 8193), (1, 0)] {
        let root = fixture("writer-delivery");
        let spool = root.join("spool");
        std::fs::create_dir(&spool).unwrap();
        std::fs::write(spool.join("keep.txt"), b"untouched").unwrap();
        let inspect_spool = spool.clone();
        let destination = root.join("received");
        let expected: Vec<u8> = (0u8..=255).cycle().take(length).collect();
        let bytes = expected.clone();
        let output = destination.clone();
        let received = run_native(workers, async move {
            let cx = Cx::current().unwrap();
            let scope = cx.scope();
            let timeout = Duration::from_secs(20);
            let sender = native_client("writer", sender_config("localhost", timeout), 1);
            let receiver_client = native_client("writer-peer", receiver_config(timeout), 1);
            let receiver = receiver_client.bind_receiver(
                &cx, "127.0.0.1:0".parse().unwrap(), output, QuicReceiveOptions::default(),
            ).await.unwrap();
            let mut writer = sender.open_writer(
                &cx, &scope, receiver.local_addr(), NativeUploadOptions::new(spool, "output.bin"),
            ).unwrap();
            for chunk in bytes.chunks(4093) {
                writer.write_all(chunk).await.unwrap();
            }
            writer.flush().await.unwrap();
            assert_eq!(writer.accepted_bytes(), length as u64);
            assert_eq!(writer.spooled_bytes(), length as u64);
            assert_eq!(writer.buffered_bytes(), 0);
            assert!(writer.buffer_high_water() <= writer.buffer_capacity());
            assert!(writer.terminal().is_none(), "local flush is not delivery");
            assert_eq!(sender.active_transfers(), 1);

            // The remote has not been polled. A correct shutdown cannot be
            // ready, even for an empty object. Dropping this wait must retain
            // the worker and the same EOF, not abort or manufacture a receipt.
            {
                let mut shutdown = Box::pin(writer.shutdown());
                assert!(shutdown.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
            }
            assert!(writer.terminal().is_none());
            let (closed, received) = zip(writer.shutdown(), receiver.receive(&cx)).await;
            closed.expect("shutdown requires native verified delivery and cleanup");
            let received = received.unwrap();
            let report = writer.finish().await.as_ref().expect("actual worker join");
            let sent = report.outcome.as_ref().expect("actual peer receipt");
            assert!(sent.receipt.committed && sent.receipt.sha_ok && sent.receipt.merkle_ok);
            assert_eq!(sent.transfer_id, received.transfer_id);
            assert_eq!(report.spooled_bytes, length as u64);
            let hash: [u8; 32] = Sha256::digest(&bytes).into();
            assert_eq!(report.source_sha256, Some(hash));
            assert!(report.cleanup_error.is_none());
            let id = sent.transfer_id.clone();
            writer.shutdown().await.unwrap();
            assert_eq!(writer.finish().await.as_ref().unwrap().outcome.as_ref().unwrap().transfer_id, id);
            assert_eq!(writer.write_all(b"late").await.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
            assert_eq!(sender.active_transfers(), 0);
            assert_eq!(receiver_client.active_transfers(), 0);
            received
        });
        assert_content(&received, &destination, "output.bin", &expected);
        assert_clean(&inspect_spool);
    }
}

#[test]
fn native_writer_pending_write_is_cancel_safe_and_capacity_is_pre_enqueued() {
    let root = fixture("writer-backpressure");
    std::fs::write(root.join("keep.txt"), b"untouched").unwrap();
    let inspect = root.clone();
    run_native(1, async move {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
        sink.set_nonblocking(true).unwrap();
        let mut config = sender_config("localhost", Duration::from_secs(2));
        config.chunk_size = 7;
        let sender = native_client("writer-backpressure", config, 1);
        let options = NativeUploadOptions::new(&root, "queued.bin");
        let mut writer = sender.open_writer(&cx, &scope, sink.local_addr().unwrap(), options.clone()).unwrap();
        assert_eq!(sender.active_transfers(), 1);
        assert!(matches!(sender.clone().open_writer(&cx, &scope, sink.local_addr().unwrap(), options),
            Err(NativeUploadError::Native(NativeTransferError::CapacityExceeded { limit: 1 }))));
        {
            let mut ctx = Context::from_waker(Waker::noop());
            assert!(matches!(Pin::new(&mut writer).poll_write(&mut ctx, b"123456789"), Poll::Ready(Ok(7))));
            let mut pending = Box::pin(writer.write_all(b"not-accepted"));
            for _ in 0..16 { assert!(pending.as_mut().poll(&mut ctx).is_pending()); }
        }
        assert_eq!(writer.accepted_bytes(), 7, "dropping a pending write cannot commit bytes");
        writer.flush().await.unwrap();
        assert_eq!(writer.spooled_bytes(), 7);
        assert!(writer.terminal().is_none());
        let mut packet = [0u8; 2048];
        assert_eq!(sink.recv_from(&mut packet).unwrap_err().kind(), io::ErrorKind::WouldBlock,
            "local flush must not start the manifest-first network transfer");
        let reason = CancelReason::user("cancel unclosed writer");
        assert_cancelled(writer.cancel_and_wait(reason.clone()).await, &reason);
        assert_eq!(sender.active_transfers(), 0);
        assert_eq!(sink.recv_from(&mut packet).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    });
    assert_clean(&inspect);
}

#[test]
fn native_writer_drop_aborts_instead_of_publishing_a_partial_object() {
    for workers in [1, 2] {
        let root = fixture("writer-drop");
        std::fs::write(root.join("keep.txt"), b"untouched").unwrap();
        let inspect = root.clone();
        run_native(workers, async move {
            let cx = Cx::current().unwrap();
            let scope = cx.scope();
            let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
            sink.set_nonblocking(true).unwrap();
            let sender = native_client("writer-drop", sender_config("localhost", Duration::from_secs(2)), 1);
            let mut writer = sender.open_writer(&cx, &scope, sink.local_addr().unwrap(),
                NativeUploadOptions::new(&root, "partial.bin")).unwrap();
            writer.write_all(b"this is only a prefix").await.unwrap();
            writer.flush().await.unwrap();
            drop(writer);
            asupersync::time::timeout(cx.now(), Duration::from_secs(5), async {
                while sender.active_transfers() != 0 { asupersync::runtime::yield_now().await; }
            }).await.expect("dropped writer must drain and release admission");
            let mut packet = [0u8; 2048];
            assert_eq!(sink.recv_from(&mut packet).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        });
        assert_clean(&inspect);
    }
}

#[test]
fn native_writer_worker_failure_wakes_pending_producer_and_retains_typed_error() {
    let root = fixture("writer-spool-error");
    std::fs::write(root.join("keep.txt"), b"untouched").unwrap();
    let inspect = root.clone();
    run_native(1, async move {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let mut config = sender_config("localhost", Duration::from_secs(2));
        config.chunk_size = 1;
        let sender = native_client("writer-spool-error", config, 1);
        let mut writer = sender.open_writer(&cx, &scope, "127.0.0.1:9".parse().unwrap(),
            NativeUploadOptions::new(root.join("missing-parent"), "error.bin")).unwrap();
        {
            let mut ctx = Context::from_waker(Waker::noop());
            assert!(matches!(Pin::new(&mut writer).poll_write(&mut ctx, b"x"), Poll::Ready(Ok(1))));
        }
        let error = asupersync::time::timeout(cx.now(), Duration::from_secs(5), writer.write_all(b"y"))
            .await.expect("failure before the first source read must wake a blocked writer")
            .expect_err("spool creation must fail");
        assert!(matches!(error.kind(), io::ErrorKind::NotFound | io::ErrorKind::BrokenPipe));
        let report = writer.finish().await.as_ref().unwrap();
        assert!(matches!(&report.outcome, Err(NativeUploadError::Io(error)) if error.kind() == io::ErrorKind::NotFound));
        assert_eq!(report.spooled_bytes, 0);
        assert!(report.cleanup_error.is_none());
        assert_eq!(sender.active_transfers(), 0);
    });
    assert_clean(&inspect);
}

#[test]
fn native_writer_oversize_cannot_turn_shutdown_into_prefix_success() {
    let root = fixture("writer-oversize");
    std::fs::write(root.join("keep.txt"), b"untouched").unwrap();
    let inspect = root.clone();
    run_native(1, async move {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
        sink.set_nonblocking(true).unwrap();
        let mut config = sender_config("localhost", Duration::from_secs(2));
        config.max_transfer_bytes = 31;
        let sender = native_client("writer-oversize", config, 1);
        let mut writer = sender.open_writer(&cx, &scope, sink.local_addr().unwrap(),
            NativeUploadOptions::new(&root, "too-large.bin")).unwrap();
        // Queued bytes are not a size/integrity receipt; the uploader rejects
        // the oversize input before any remote connection is established.
        writer.write_all(&[7; 32]).await.unwrap();
        assert!(writer.shutdown().await.is_err());
        let report = writer.finish().await.as_ref().unwrap();
        assert!(matches!(&report.outcome, Err(NativeUploadError::TooLarge { limit: 31 })));
        assert!(report.source_sha256.is_none());
        assert!(report.cleanup_error.is_none());
        let mut packet = [0u8; 2048];
        assert_eq!(sink.recv_from(&mut packet).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(sender.active_transfers(), 0);
    });
    assert_clean(&inspect);
}

#[test]
fn native_writer_shutdown_does_not_succeed_when_a_peer_never_answers() {
    let root = fixture("writer-silent-peer");
    std::fs::write(root.join("keep.txt"), b"untouched").unwrap();
    let inspect = root.clone();
    run_native(1, async move {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender = native_client("writer-silent-peer",
            sender_config("localhost", Duration::from_millis(100)), 1);
        let mut writer = sender.open_writer(&cx, &scope, sink.local_addr().unwrap(),
            NativeUploadOptions::new(&root, "unacknowledged.bin")).unwrap();
        writer.write_all(b"not remotely acknowledged").await.unwrap();
        writer.flush().await.unwrap();
        let result = asupersync::time::timeout(cx.now(), Duration::from_secs(5), writer.shutdown())
            .await.expect("configured transport timeout must terminate");
        assert!(result.is_err(), "EOF/local flush cannot fabricate a peer receipt");
        let report = writer.finish().await.as_ref().unwrap();
        assert!(matches!(&report.outcome, Err(NativeUploadError::Native(_))));
        assert!(report.cleanup_error.is_none());
        assert_eq!(sender.active_transfers(), 0);
    });
    assert_clean(&inspect);
}
