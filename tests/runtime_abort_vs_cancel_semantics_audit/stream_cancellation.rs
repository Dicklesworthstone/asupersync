//! Channel streams must observe cancellation without a producer event.

use super::*;
use asupersync::channel::{broadcast, watch};
use asupersync::stream::{BroadcastStream, ReceiverStream, Stream, WatchStream};

#[derive(Clone, Copy, Debug)]
enum ChannelKind {
    Mpsc,
    Watch,
    Broadcast,
}

enum ChannelSource {
    Mpsc(mpsc::Sender<u8>),
    Watch(watch::Sender<u8>),
    Broadcast(broadcast::Sender<u8>),
}

impl ChannelSource {
    fn waiters(&self) -> usize {
        match self {
            Self::Mpsc(sender) => sender.telemetry_snapshot(1).recv_waiter_count,
            Self::Watch(sender) => sender.telemetry_snapshot(1).recv_waiter_count,
            Self::Broadcast(sender) => sender.telemetry_snapshot(1).recv_waiter_count,
        }
    }

    // Used only after recording a failed cancellation-only wake. This makes
    // the old implementation fail cleanly instead of leaving a parked child.
    fn wake_for_failure_cleanup(&self, cx: &Cx) {
        match self {
            Self::Mpsc(sender) => sender.try_send(1).expect("failure-only MPSC wake"),
            Self::Watch(sender) => sender.send(1).expect("failure-only watch wake"),
            Self::Broadcast(sender) => {
                sender.send(cx, 1).expect("failure-only broadcast wake");
            }
        }
    }
}

enum ChannelStream {
    Mpsc(ReceiverStream<u8>),
    Watch(WatchStream<u8>),
    Broadcast(BroadcastStream<u8>),
}

impl ChannelStream {
    fn new(kind: ChannelKind, cx: Cx) -> (Self, ChannelSource) {
        match kind {
            ChannelKind::Mpsc => {
                let (sender, receiver) = mpsc::channel(2);
                (
                    Self::Mpsc(ReceiverStream::new(cx, receiver)),
                    ChannelSource::Mpsc(sender),
                )
            }
            ChannelKind::Watch => {
                let (sender, receiver) = watch::channel(0);
                (
                    Self::Watch(WatchStream::from_changes(cx, receiver)),
                    ChannelSource::Watch(sender),
                )
            }
            ChannelKind::Broadcast => {
                let (sender, receiver) = broadcast::channel(2);
                (
                    Self::Broadcast(BroadcastStream::new(cx, receiver)),
                    ChannelSource::Broadcast(sender),
                )
            }
        }
    }

    fn poll_end(&mut self, task: &mut Context<'_>) -> Poll<bool> {
        match self {
            Self::Mpsc(stream) => Pin::new(stream).poll_next(task).map(|item| item.is_none()),
            Self::Watch(stream) => Pin::new(stream).poll_next(task).map(|item| item.is_none()),
            Self::Broadcast(stream) => Pin::new(stream).poll_next(task).map(|item| item.is_none()),
        }
    }
}

fn independent_stream_cancellation_on_native(sharded: bool, kind: ChannelKind) {
    let runtime = checked_native_runtime(sharded, 16);
    let parent: Pin<Box<dyn std::future::Future<Output = bool> + Send>> = Box::pin(async move {
        let parent_cx: Cx = Cx::current().expect("native parent context");
        let (context_sender, mut context_receiver) = oneshot::channel::<Cx>();
        let (release_owner, mut owner_released) = oneshot::channel::<()>();
        let mut owner = parent_cx
            .spawn(move |owner_cx| {
                let future: Pin<Box<dyn std::future::Future<Output = ()> + Send>> =
                    Box::pin(async move {
                        context_sender
                            .send_blocking(owner_cx.clone())
                            .expect("publish actual admitted operation context");
                        // Keep this actual owner and its cancellation registry live
                        // until the stream has retired. Its primary cancellation
                        // waker belongs to this task, not to the stream's task.
                        let cleanup_cx = Cx::<asupersync::cx::cap::None>::detached_cancel_context();
                        assert_eq!(owner_released.recv(&cleanup_cx).await, Ok(()));
                        assert!(owner_cx.checkpoint().is_err());
                    });
                future
            })
            .expect("spawn operation-context owner");
        let operation_cx = context_receiver
            .recv(&parent_cx)
            .await
            .expect("receive runtime-wired operation context");
        let operation_task = operation_cx.task_id();
        let cancel_cx = operation_cx.clone();
        let (mut stream, source) = ChannelStream::new(kind, operation_cx);
        let (release_stream, mut stream_released) = oneshot::channel::<()>();
        let parked = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(AtomicBool::new(false));
        let child_parked = Arc::clone(&parked);
        let child_completed = Arc::clone(&completed);
        let mut waiter = parent_cx
            .spawn(move |child_cx| {
                let future: Pin<Box<dyn std::future::Future<Output = ()> + Send>> =
                    Box::pin(async move {
                        assert_ne!(child_cx.task_id(), operation_task);
                        assert!(!child_cx.is_cancel_requested());
                        let ended = std::future::poll_fn(|task| {
                            let result = stream.poll_end(task);
                            if result.is_pending() {
                                child_parked.store(true, Ordering::Release);
                            }
                            result
                        })
                        .await;
                        assert!(
                            ended,
                            "cancellation must terminate the stream without an item"
                        );
                        assert!(!child_cx.is_cancel_requested());
                        child_completed.store(true, Ordering::Release);
                        // Retain the stream so the parent's waiter-count assertion
                        // cannot pass merely because the entire adapter was dropped.
                        assert_eq!(stream_released.recv(&child_cx).await, Ok(()));
                        drop(stream);
                    });
                future
            })
            .expect("spawn actual native stream poller");

        assert!(drive_until_flag(&parked, Duration::from_secs(2)).await);
        assert_eq!(source.waiters(), 1);
        std::thread::spawn(move || cancel_cx.cancel_fast(CancelKind::User))
            .join()
            .expect("independent operation cancellation thread");
        let completed_without_producer = drive_until_flag(&completed, Duration::from_secs(2)).await;
        if !completed_without_producer {
            source.wake_for_failure_cleanup(&parent_cx);
            assert!(drive_until_flag(&completed, Duration::from_secs(2)).await);
        }
        assert_eq!(source.waiters(), 0);
        assert!(!parent_cx.is_cancel_requested());
        release_stream
            .send_blocking(())
            .expect("release retained stream");
        assert_eq!(waiter.join(&parent_cx).await, Ok(()));
        release_owner
            .send_blocking(())
            .expect("release context owner");
        assert_eq!(owner.join(&parent_cx).await, Ok(()));
        completed_without_producer
    });
    let completed_without_producer = runtime.block_on(runtime.handle().spawn(parent));
    assert_checked_native_cleanup(&runtime);
    assert!(runtime.shutdown_timeout(Duration::from_secs(5)));
    assert!(
        completed_without_producer,
        "{kind:?} stream stayed parked after its independent Cx was cancelled; sharded={sharded}"
    );
}

#[test]
fn channel_streams_cancel_without_producer_on_native_current_thread() {
    for kind in [
        ChannelKind::Mpsc,
        ChannelKind::Watch,
        ChannelKind::Broadcast,
    ] {
        independent_stream_cancellation_on_native(false, kind);
    }
}

#[test]
fn channel_streams_cancel_without_producer_on_native_sharded_workers() {
    for kind in [
        ChannelKind::Mpsc,
        ChannelKind::Watch,
        ChannelKind::Broadcast,
    ] {
        independent_stream_cancellation_on_native(true, kind);
    }
}
