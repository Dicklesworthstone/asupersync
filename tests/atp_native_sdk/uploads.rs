//! Additional public upload journeys, compiled through atp_native_sdk_transfer.

use super::{assert_content, fixture, native_client, receiver_config, run_native, sender_config};
use asupersync::Cx;
use asupersync::io::{AsyncRead, ReadBuf};
use asupersync::net::atp::sdk::native::{NativeUploadError, NativeUploadOptions};
use asupersync::net::atp::sdk::NativeTransferError;
use asupersync::net::atp::transport_quic::QuicReceiveOptions;
use asupersync::runtime::JoinError;
use asupersync::types::CancelReason;
use futures_lite::future::zip;
use sha2::{Digest, Sha256};
use std::io;
use std::net::UdpSocket;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

struct ChunkedInput {
    bytes: Vec<u8>,
    offset: usize,
    pending: bool,
}

impl AsyncRead for ChunkedInput {
    fn poll_read(mut self: Pin<&mut Self>, ctx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        assert!(buf.remaining() <= 4096, "SDK must honor the stricter read buffer cap");
        if self.pending {
            self.pending = false;
            ctx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let count = (self.bytes.len() - self.offset).min(buf.remaining()).min(4093);
        buf.put_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        self.pending = true;
        Poll::Ready(Ok(()))
    }
}

struct ParkedInput(Arc<AtomicBool>);

impl AsyncRead for ParkedInput {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.0.store(true, Ordering::SeqCst);
        // Deliberately no wake: the SDK must supply the cancellation/timeout wake.
        Poll::Pending
    }
}

fn assert_empty_spool(parent: &Path) {
    assert_eq!(std::fs::read_dir(parent).unwrap().count(), 1);
    assert_eq!(std::fs::read(parent.join("keep.txt")).unwrap(), b"untouched");
}

#[test]
fn native_upload_async_reader_and_buffer_deliver_real_verified_objects() {
    for (workers, use_buffer, length) in [(1, false, 128 * 1024 + 17), (2, true, 8193), (1, true, 0)] {
        let root = fixture("upload-success");
        let spool = root.join("spool");
        std::fs::create_dir(&spool).unwrap();
        std::fs::write(spool.join("keep.txt"), b"untouched").unwrap();
        let expected: Vec<u8> = (0u8..=255).cycle().take(length).collect();
        let destination = root.join("received");
        let receive_root = destination.clone();
        let inspect_spool = spool.clone();
        let data = expected.clone();
        let (report, received) = run_native(workers, async move {
            let cx = Cx::current().unwrap();
            let timeout = Duration::from_secs(20);
            let sender = native_client("upload-sender", sender_config("localhost", timeout), 1);
            let receiver_client = native_client("upload-receiver", receiver_config(timeout), 1);
            let receiver = receiver_client.bind_receiver(
                &cx, "127.0.0.1:0".parse().unwrap(), receive_root, QuicReceiveOptions::default(),
            ).await.unwrap();
            let remote = receiver.local_addr();
            let options = NativeUploadOptions::new(spool, "object.bin");
            let (report, received) = if use_buffer {
                zip(sender.send_buffer(&cx, remote, options, &data), receiver.receive(&cx)).await
            } else {
                let scope = cx.scope();
                let reader = ChunkedInput { bytes: data, offset: 0, pending: true };
                let mut task = sender.spawn_send_reader(&cx, &scope, remote, options, reader).unwrap();
                let (joined, received) = zip(task.join(&cx), receiver.receive(&cx)).await;
                (joined.expect("upload worker joined"), received)
            };
            assert_eq!(sender.active_transfers(), 0);
            assert_eq!(receiver_client.active_transfers(), 0);
            (report, received.unwrap())
        });
        assert!(report.cleanup_error.is_none(), "{report:?}");
        assert_eq!(report.spooled_bytes, length as u64);
        let digest: [u8; 32] = Sha256::digest(&expected).into();
        assert_eq!(report.source_sha256, Some(digest));
        let sent = report.outcome.expect("verified peer receipt required");
        assert!(sent.receipt.committed && sent.receipt.sha_ok && sent.receipt.merkle_ok);
        assert_eq!(sent.transfer_id, received.transfer_id);
        assert_content(&received, &destination, "object.bin", &expected);
        assert_empty_spool(&inspect_spool);
    }
}

#[test]
fn native_upload_oversize_and_read_failure_never_contact_the_peer() {
    struct FailsAfterPrefix(bool);
    impl AsyncRead for FailsAfterPrefix {
        fn poll_read(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            if self.0 {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "input failed")));
            }
            self.0 = true;
            buf.put_slice(b"prefix");
            Poll::Ready(Ok(()))
        }
    }
    let root = fixture("upload-refusal");
    std::fs::write(root.join("keep.txt"), b"untouched").unwrap();
    let inspect = root.clone();
    run_native(1, async move {
        let cx = Cx::current().unwrap();
        let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
        sink.set_nonblocking(true).unwrap();
        let mut config = sender_config("localhost", Duration::from_secs(2));
        config.max_transfer_bytes = 31;
        let sender = native_client("bounded-upload", config, 1);
        let mut options = NativeUploadOptions::new(&root, "over-limit.bin");
        options.max_bytes = Some(100); // Must not widen the native 31-byte cap.
        let report = sender.send_buffer(&cx, sink.local_addr().unwrap(), options, &[7; 32]).await;
        assert!(matches!(report.outcome, Err(NativeUploadError::TooLarge { limit: 31 })));
        assert!(report.spooled_bytes <= 31);
        assert!(report.source_sha256.is_none());
        assert!(report.cleanup_error.is_none());
        let report = sender.send_reader(
            &cx, sink.local_addr().unwrap(), NativeUploadOptions::new(&root, "failed.bin"),
            FailsAfterPrefix(false),
        ).await;
        assert!(matches!(report.outcome, Err(NativeUploadError::Io(ref error)) if error.kind() == io::ErrorKind::UnexpectedEof));
        assert_eq!(report.spooled_bytes, 6);
        assert!(report.source_sha256.is_none());
        assert!(report.cleanup_error.is_none());
        assert_eq!(sender.active_transfers(), 0);
        let mut packet = [0u8; 2048];
        assert_eq!(sink.recv_from(&mut packet).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    });
    assert_empty_spool(&inspect);
}

#[test]
fn native_upload_stalled_source_times_out_instead_of_reporting_eof() {
    let root = fixture("upload-source-timeout");
    std::fs::write(root.join("keep.txt"), b"untouched").unwrap();
    let inspect = root.clone();
    run_native(1, async move {
        let cx = Cx::current().unwrap();
        let sender = native_client("upload-timeout", sender_config("localhost", Duration::from_secs(2)), 1);
        let entered = Arc::new(AtomicBool::new(false));
        let mut options = NativeUploadOptions::new(&root, "stalled.bin");
        options.source_idle_timeout = Duration::from_millis(25);
        let report = sender.send_reader(
            &cx, "127.0.0.1:9".parse().unwrap(), options, ParkedInput(Arc::clone(&entered)),
        ).await;
        assert!(entered.load(Ordering::SeqCst));
        assert!(matches!(report.outcome, Err(NativeUploadError::SourceTimeout)));
        assert!(report.source_sha256.is_none());
        assert!(report.cleanup_error.is_none());
        assert_eq!(sender.active_transfers(), 0);
    });
    assert_empty_spool(&inspect);
}

#[test]
fn native_upload_cancellation_wakes_a_source_that_never_wakes_itself() {
    let root = fixture("upload-source-cancel");
    std::fs::write(root.join("keep.txt"), b"untouched").unwrap();
    let inspect = root.clone();
    run_native(2, async move {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let sender = native_client("upload-cancel", sender_config("localhost", Duration::from_secs(2)), 1);
        let entered = Arc::new(AtomicBool::new(false));
        let mut options = NativeUploadOptions::new(&root, "cancelled.bin");
        options.source_idle_timeout = Duration::from_secs(3600);
        let mut task = sender.spawn_send_reader(
            &cx, &scope, "127.0.0.1:9".parse().unwrap(), options, ParkedInput(Arc::clone(&entered)),
        ).unwrap();
        asupersync::time::timeout(cx.now(), Duration::from_secs(5), async {
            while !entered.load(Ordering::SeqCst) { asupersync::runtime::yield_now().await; }
        }).await.expect("source must actually begin waiting");
        assert_eq!(sender.active_transfers(), 1);
        let reason = CancelReason::user("cancel stalled SDK input");
        task.abort_with_reason(reason.clone());
        let joined = asupersync::time::timeout(cx.now(), Duration::from_secs(5), task.join(&cx))
            .await.expect("cancellation must not wait for the one-hour source timeout");
        match joined {
            Ok(report) => {
                assert!(matches!(report.outcome, Err(NativeUploadError::Cancelled { reason: Some(ref actual) }) if actual == &reason));
                assert!(report.cleanup_error.is_none());
            }
            Err(JoinError::Cancelled(actual)) => assert_eq!(actual, reason),
            other => panic!("wrong terminal result: {other:?}"),
        }
        assert_eq!(sender.active_transfers(), 0);
    });
    assert_empty_spool(&inspect);
}

#[test]
fn native_upload_admission_precedes_source_polling_and_spool_creation() {
    let root = fixture("upload-admission");
    std::fs::write(root.join("keep.txt"), b"untouched").unwrap();
    let inspect = root.clone();
    run_native(1, async move {
        let cx = Cx::current().unwrap();
        let scope = cx.scope();
        let sender = native_client("upload-admission", sender_config("localhost", Duration::from_secs(2)), 1);
        let entered = Arc::new(AtomicBool::new(false));
        let options = NativeUploadOptions::new(&root, "queued.bin");
        let mut first = sender.spawn_send_reader(
            &cx, &scope, "127.0.0.1:9".parse().unwrap(), options.clone(), ParkedInput(Arc::clone(&entered)),
        ).unwrap();
        assert_eq!(sender.active_transfers(), 1);
        assert!(!entered.load(Ordering::SeqCst));
        assert_empty_spool(&root);
        assert!(matches!(sender.clone().spawn_send_reader(
            &cx, &scope, "127.0.0.1:9".parse().unwrap(), options, ParkedInput(Arc::clone(&entered)),
        ), Err(NativeUploadError::Native(NativeTransferError::CapacityExceeded { limit: 1 }))));
        first.abort_with_reason(CancelReason::user("cancel queued upload"));
        let joined = first.join(&cx).await;
        assert!(matches!(joined, Err(JoinError::Cancelled(_))));
        assert!(!entered.load(Ordering::SeqCst));
        assert_eq!(sender.active_transfers(), 0);
    });
    assert_empty_spool(&inspect);
}

#[test]
fn native_upload_missing_capability_never_polls_or_spools_input() {
    let root = fixture("upload-authority");
    std::fs::write(root.join("keep.txt"), b"untouched").unwrap();
    let inspect = root.clone();
    run_native(1, async move {
        let sender = native_client("no-io", sender_config("localhost", Duration::from_secs(2)), 1);
        // Ambient lookup preserves runtime attenuation even though its return
        // type is Cx<All>. Release the thread-local guard before any await;
        // the captured context retains the narrowed mask.
        let cx = {
            let _restriction = Cx::push_restriction(asupersync::cx::cap::CapMask::none());
            Cx::current().expect("native runtime installs a context")
        };
        let caps = cx.capabilities();
        assert!(!caps.io && !caps.entropy && !caps.time);
        let entered = Arc::new(AtomicBool::new(false));
        let report = sender.send_reader(&cx, "127.0.0.1:9".parse().unwrap(),
            NativeUploadOptions::new(root, "denied.bin"), ParkedInput(Arc::clone(&entered))).await;
        assert!(matches!(report.outcome, Err(NativeUploadError::MissingCapability)));
        assert!(!entered.load(Ordering::SeqCst));
        assert_eq!(sender.active_transfers(), 0);
    });
    assert_empty_spool(&inspect);
}
