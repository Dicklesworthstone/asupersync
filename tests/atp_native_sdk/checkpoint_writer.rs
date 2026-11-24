//! Writable durable preparation, process restart, and real authenticated delivery.

use super::{
    child_context, client, config, data, exclusive, finish_child, fixture, no_packet, run,
    run_on, saved, sender, start_child,
};
use asupersync::Cx;
use asupersync::io::{AsyncWrite, AsyncWriteExt};
use asupersync::net::atp::sdk::native::upload::NativeCheckpointWriterTerminal;
use asupersync::net::atp::sdk::native::upload::recovery::{
    NativeCheckpointError, NativeCheckpointRetry, NativeCheckpointState,
};
use asupersync::net::atp::sdk::native::{
    NativeTransferError, NativeUploadError, NativeUploadOptions,
};
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

fn assert_clean(root: &Path) {
    assert_eq!(std::fs::read_dir(root).unwrap().count(), 1);
    assert_eq!(std::fs::read(root.join("keep")).unwrap(), b"unrelated");
}

fn assert_cancelled(result: &NativeCheckpointWriterTerminal, reason: &CancelReason) {
    match result.outcome.as_ref() {
        Some(Err(NativeCheckpointError::Upload(NativeUploadError::Cancelled {
            reason: Some(actual),
        }))) => assert_eq!(actual, reason),
        None => assert!(matches!(
            &result.join,
            Err(JoinError::Cancelled(actual)) if actual == reason
        )),
        other => panic!("unexpected checkpoint writer cancellation: {other:?}"),
    }
    if let Err(error) = &result.join {
        assert!(matches!(error, JoinError::Cancelled(actual) if actual == reason));
    }
}

#[test]
fn checkpoint_writer_survives_producer_exit_and_reuses_receipt() {
    let _exclusive = exclusive();
    if let Some((root, remote)) = child_context("prepare-writer") {
        run(async move {
            let cx = Cx::current().unwrap();
            let scope = cx.scope();
            let sender = sender();
            let mut writer = sender
                .open_checkpoint_writer(
                    &cx,
                    &scope,
                    remote,
                    NativeUploadOptions::new(&root, "data.bin"),
                )
                .unwrap();
            let bytes = data();
            for chunk in bytes.chunks(4093) {
                writer.write_all(chunk).await.unwrap();
            }
            writer.flush().await.unwrap();
            assert_eq!(writer.accepted_bytes(), bytes.len() as u64);
            assert_eq!(writer.spooled_bytes(), bytes.len() as u64);
            assert_eq!(writer.buffered_bytes(), 0);
            assert!(writer.buffer_high_water() <= writer.buffer_capacity());
            assert!(writer.terminal().is_none(), "flush cannot publish before EOF");
            assert_eq!(sender.active_transfers(), 1);
            {
                // Current-thread worker cannot finish publication during this
                // synchronous poll. Dropping the wait must retain its EOF.
                let mut shutdown = Box::pin(writer.shutdown());
                assert!(
                    shutdown
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
            }
            writer.shutdown().await.unwrap();
            let terminal = writer.finish().await;
            assert!(terminal.join.is_ok());
            let prepared = terminal.outcome.as_ref().unwrap().as_ref().unwrap();
            assert!(prepared.cleanup_error.is_none());
            assert_eq!(prepared.checkpoint.state, NativeCheckpointState::Prepared);
            assert_eq!(prepared.checkpoint.attempt, 0);
            assert_eq!(prepared.checkpoint.source_bytes, bytes.len() as u64);
            let digest: [u8; 32] = Sha256::digest(&bytes).into();
            assert_eq!(prepared.checkpoint.source_sha256, digest);
            let checkpoint = prepared.checkpoint.clone();
            writer.shutdown().await.unwrap();
            assert_eq!(
                writer
                    .finish()
                    .await
                    .outcome
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .checkpoint,
                checkpoint
            );
            assert_eq!(
                writer.write_all(b"late").await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
            assert_eq!(sender.active_transfers(), 0);
            std::fs::write(
                root.join("checkpoint-path"),
                checkpoint.directory.to_str().unwrap(),
            )
            .unwrap();
        });
        return;
    }

    let root = fixture();
    let retained_root = root.clone();
    let witness = UdpSocket::bind("127.0.0.1:0").unwrap();
    let remote = witness.local_addr().unwrap();
    let mut child = start_child(
        "writer::checkpoint_writer_survives_producer_exit_and_reuses_receipt",
        &root,
        remote,
        "prepare-writer",
    );
    finish_child(&mut child);
    no_packet(&witness); // Even successful EOF performs no handshake or send.
    drop(witness);
    let (directory, transfer_id) = run(async move {
        let cx = Cx::current().unwrap();
        let receiving = client("checkpoint-writer-receiver", config("localhost", true), 1);
        let receiver = receiving
            .bind_receiver(
                &cx,
                remote,
                root.join("received"),
                QuicReceiveOptions::default(),
            )
            .await
            .unwrap();
        let directory = saved(&root);
        let sending = sender(); // New process/client, with no original writer task.
        let (attempt, received) = zip(
            sending.send_checkpoint(&cx, &directory, remote, NativeCheckpointRetry::Never),
            receiver.receive(&cx),
        )
        .await;
        let attempt = attempt.unwrap();
        assert!(!attempt.cached_receipt);
        assert!(attempt.persistence_error.is_none());
        assert_eq!(attempt.checkpoint.state, NativeCheckpointState::Acknowledged);
        assert_eq!(attempt.checkpoint.attempt, 1);
        let sent = attempt.outcome.unwrap();
        let received = received.unwrap();
        assert!(sent.receipt.committed && sent.receipt.sha_ok && sent.receipt.merkle_ok);
        assert_eq!(sent.transfer_id, received.transfer_id);
        assert_eq!(received.committed_paths.len(), 1);
        assert_eq!(std::fs::read(&received.committed_paths[0]).unwrap(), data());
        assert_eq!(sending.active_transfers(), 0);
        (directory, sent.transfer_id)
    });
    let witness = UdpSocket::bind(remote).unwrap();
    run(async move {
        let cx = Cx::current().unwrap();
        let cached = sender()
            .send_checkpoint(&cx, &directory, remote, NativeCheckpointRetry::Never)
            .await
            .unwrap();
        assert!(cached.cached_receipt);
        assert!(cached.persistence_error.is_none());
        assert_eq!(cached.outcome.unwrap().transfer_id, transfer_id);
        assert_eq!(std::fs::read(directory.join("payload/data.bin")).unwrap(), data());
    });
    no_packet(&witness);
    assert_eq!(std::fs::read(retained_root.join("keep")).unwrap(), b"unrelated");
}

#[test]
fn checkpoint_writer_bounds_input_and_reserves_before_enqueue() {
    let _exclusive = exclusive();
    let root = fixture();
    let inspect = root.clone();
    run(async move {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let witness = UdpSocket::bind("127.0.0.1:0").unwrap();
        let remote = witness.local_addr().unwrap();
        let mut cfg = config("localhost", false);
        cfg.chunk_size = 7;
        let sending = client("checkpoint-queued-writer", cfg, 1);
        let options = NativeUploadOptions::new(&root, "data.bin");
        let mut writer = sending
            .open_checkpoint_writer(&cx, &scope, remote, options.clone())
            .unwrap();
        assert_eq!(sending.active_transfers(), 1);
        assert!(matches!(
            sending.clone().open_checkpoint_writer(&cx, &scope, remote, options),
            Err(NativeCheckpointError::Native(
                NativeTransferError::CapacityExceeded { limit: 1 }
            ))
        ));
        {
            let mut ctx = Context::from_waker(Waker::noop());
            assert!(matches!(
                Pin::new(&mut writer).poll_write(&mut ctx, b"123456789"),
                Poll::Ready(Ok(7))
            ));
            let mut pending = Box::pin(writer.write_all(b"not accepted"));
            for _ in 0..16 {
                assert!(pending.as_mut().poll(&mut ctx).is_pending());
            }
        }
        assert_eq!(writer.accepted_bytes(), 7);
        assert_eq!(writer.buffered_bytes(), 7);
        assert_eq!(writer.buffer_high_water(), writer.buffer_capacity());
        let reason = CancelReason::user("cancel before checkpoint worker starts");
        assert_cancelled(writer.cancel_and_wait(reason.clone()).await, &reason);
        assert_eq!(sending.active_transfers(), 0);
        no_packet(&witness);
    });
    assert_clean(&inspect);
}

#[test]
fn checkpoint_writer_cancellation_and_drop_drain_without_publishing_prefixes() {
    let _exclusive = exclusive();
    for (workers, cancel) in [(1, true), (2, true), (1, false), (2, false)] {
        let root = fixture();
        let inspect = root.clone();
        run_on(workers, async move {
            let cx = Cx::current().unwrap();
            let scope = cx.scope();
            let witness = UdpSocket::bind("127.0.0.1:0").unwrap();
            let sending = sender();
            let mut writer = sending
                .open_checkpoint_writer(
                    &cx,
                    &scope,
                    witness.local_addr().unwrap(),
                    NativeUploadOptions::new(&root, "partial.bin"),
                )
                .unwrap();
            writer.write_all(b"only the beginning").await.unwrap();
            writer.flush().await.unwrap();
            assert!(writer.terminal().is_none());
            if cancel {
                let reason = CancelReason::user("cancel checkpoint waiting for EOF");
                let terminal = asupersync::time::timeout(
                    cx.now(),
                    Duration::from_secs(60),
                    writer.cancel_and_wait(reason.clone()),
                )
                .await
                .expect("parked source cancellation must wake and drain");
                assert_cancelled(terminal, &reason);
            } else {
                drop(writer);
                asupersync::time::timeout(cx.now(), Duration::from_secs(60), async {
                    while sending.active_transfers() != 0 {
                        asupersync::runtime::yield_now().await;
                    }
                })
                .await
                .expect("scope-owned dropped writer must release its admission");
            }
            assert_eq!(sending.active_transfers(), 0);
            no_packet(&witness);
        });
        assert_clean(&inspect);
    }
}
