use super::*;
use crate::io::replay::IoCaptureLimits;
use crate::io::replay_group::{
    IoGroupCaptureLimits, IoGroupCompletionError, IoRecordingGroup, RecordedIoGroup,
};

#[derive(Default)]
struct Fixture {
    input: &'static [u8],
    read_error: bool,
}
impl AsyncRead for Fixture {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if std::mem::take(&mut this.read_error) {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        let n = buf.remaining().min(this.input.len());
        buf.put_slice(&this.input[..n]);
        this.input = &this.input[n..];
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Fixture {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_write_vectored(self: Pin<&mut Self>, _: &mut Context<'_>, bufs: &[IoSlice<'_>]) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(bufs.iter().map(|buf| buf.len()).sum()))
    }
    fn is_write_vectored(&self) -> bool { true }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
}

fn group() -> IoRecordingGroup {
    IoRecordingGroup::new(IoGroupCaptureLimits {
        max_streams: 4,
        max_events: 128,
        per_stream: IoCaptureLimits::new(64, 4096, 4096, 16),
    })
}
fn read(io: &mut (impl AsyncRead + Unpin), size: usize, waker: &Waker) -> Poll<io::Result<Vec<u8>>> {
    let mut bytes = vec![0; size];
    let mut buf = ReadBuf::new(&mut bytes);
    Pin::new(io).poll_read(&mut Context::from_waker(waker), &mut buf)
        .map(|result| result.map(|()| buf.filled().to_vec()))
}
fn write(io: &mut (impl AsyncWrite + Unpin), bytes: &[u8], waker: &Waker) -> Poll<io::Result<usize>> {
    Pin::new(io).poll_write(&mut Context::from_waker(waker), bytes)
}
fn value<T>(result: Poll<io::Result<T>>) -> T {
    match result {
        Poll::Ready(Ok(value)) => value,
        _ => panic!("expected a captured successful completion"),
    }
}
fn exchange(write_first: bool) -> RecordedIoGroup {
    let group = group();
    let mut io = group.register(11, Fixture { input: b"reply", ..Fixture::default() }).unwrap();
    if write_first { value(write(&mut io, b"request", Waker::noop())); }
    assert_eq!(value(read(&mut io, 5, Waker::noop())), b"reply");
    if !write_first { value(write(&mut io, b"request", Waker::noop())); }
    io.into_inner();
    group.finish().unwrap()
}
#[derive(Default)]
struct Counter(AtomicUsize);
impl Wake for Counter {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}
fn counting() -> (Arc<Counter>, Waker) {
    let counter = Arc::new(Counter::default());
    let waker = Waker::from(Arc::clone(&counter));
    (counter, waker)
}

#[test]
fn early_read_parks_until_recorded_write_without_spurious_self_wakes() {
    let replay = exchange(true).replay();
    let (mut reader, mut writer) = replay.open(11).unwrap().into_split();
    let (count, waker) = counting();
    for _ in 0..8 { assert!(read(&mut reader, 5, &waker).is_pending()); }
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
    assert_eq!(replay.verify_complete(), Err(IoGroupCompletionError::Remaining(2)));
    assert_eq!(value(write(&mut writer, b"request", Waker::noop())), 7);
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
    assert_eq!(value(read(&mut reader, 5, &waker)), b"reply");
    drop(reader); drop(writer);
    replay.verify_complete().unwrap();
}

#[test]
fn early_write_parks_until_recorded_read() {
    let replay = exchange(false).replay();
    let (mut reader, mut writer) = replay.open(11).unwrap().into_split();
    let (count, waker) = counting();
    assert!(write(&mut writer, b"request", &waker).is_pending());
    assert_eq!(value(read(&mut reader, 5, Waker::noop())), b"reply");
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
    assert_eq!(value(write(&mut writer, b"request", &waker)), 7);
    replay.verify_complete().unwrap();
}

#[test]
fn latest_waiter_replaces_cancelled_poll_without_consuming_observations() {
    let replay = exchange(true).replay();
    let (mut reader, mut writer) = replay.open(11).unwrap().into_split();
    let (old, old_waker) = counting();
    let (new, new_waker) = counting();
    // Dropping an individual pending operation leaves its half and tape alive.
    assert!(read(&mut reader, 5, &old_waker).is_pending());
    assert!(read(&mut reader, 5, &new_waker).is_pending());
    value(write(&mut writer, b"request", Waker::noop()));
    assert_eq!(old.0.load(Ordering::SeqCst), 0);
    assert_eq!(new.0.load(Ordering::SeqCst), 1);
    assert_eq!(value(read(&mut reader, 5, &new_waker)), b"reply");
    replay.verify_complete().unwrap();
}

#[test]
fn cross_connection_prerequisite_wakes_both_parked_directions() {
    let group = group();
    let mut a = group.register(1, Fixture { input: b"a", ..Fixture::default() }).unwrap();
    let mut b = group.register(2, Fixture { input: b"b", ..Fixture::default() }).unwrap();
    value(read(&mut a, 1, Waker::noop()));
    value(write(&mut b, b"q", Waker::noop()));
    value(read(&mut b, 1, Waker::noop()));
    a.into_inner(); b.into_inner();
    let replay = group.finish().unwrap().replay();
    let mut a = replay.open(1).unwrap();
    let (mut reader, mut writer) = replay.open(2).unwrap().into_split();
    let (reads, read_waker) = counting();
    let (writes, write_waker) = counting();
    assert!(read(&mut reader, 1, &read_waker).is_pending());
    assert!(write(&mut writer, b"q", &write_waker).is_pending());
    value(read(&mut a, 1, Waker::noop()));
    assert_eq!(reads.0.load(Ordering::SeqCst), 1);
    assert_eq!(writes.0.load(Ordering::SeqCst), 1);
    assert!(read(&mut reader, 1, &read_waker).is_pending());
    value(write(&mut writer, b"q", &write_waker));
    assert_eq!(reads.0.load(Ordering::SeqCst), 2);
    assert_eq!(value(read(&mut reader, 1, &read_waker)), b"b");
    replay.verify_complete().unwrap();
}

#[test]
fn abandoned_write_half_fails_and_wakes_read_half() {
    let replay = exchange(true).replay();
    let (mut reader, writer) = replay.open(11).unwrap().into_split();
    let (count, waker) = counting();
    assert!(read(&mut reader, 5, &waker).is_pending());
    drop(writer);
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
    assert!(matches!(read(&mut reader, 5, &waker), Poll::Ready(Err(_))));
    assert_eq!(replay.verify_complete(), Err(IoGroupCompletionError::Diverged(
        IoGroupReplayError::AbandonedHalf { stream: 11, direction: ReplayDirection::Write, remaining: 1 }
    )));
}

#[test]
fn exhausted_half_can_drop_while_peer_finishes_but_extra_poll_is_divergence() {
    let replay = exchange(false).replay();
    let (mut reader, mut writer) = replay.open(11).unwrap().into_split();
    value(read(&mut reader, 5, Waker::noop()));
    drop(reader);
    value(write(&mut writer, b"request", Waker::noop()));
    drop(writer);
    replay.verify_complete().unwrap();

    let replay = exchange(false).replay();
    let (mut reader, _writer) = replay.open(11).unwrap().into_split();
    value(read(&mut reader, 5, Waker::noop()));
    assert!(matches!(read(&mut reader, 5, Waker::noop()), Poll::Ready(Err(_))));
    assert_eq!(replay.verify_complete(), Err(IoGroupCompletionError::Diverged(
        IoGroupReplayError::ExhaustedHalf { stream: 11, direction: ReplayDirection::Read }
    )));
}

#[test]
fn changed_write_and_wrong_write_operation_remain_sticky_errors() {
    let replay = exchange(true).replay();
    let (mut reader, mut writer) = replay.open(11).unwrap().into_split();
    assert!(read(&mut reader, 5, Waker::noop()).is_pending());
    assert!(matches!(write(&mut writer, b"WRONG!!", Waker::noop()), Poll::Ready(Err(_))));
    assert!(matches!(read(&mut reader, 5, Waker::noop()), Poll::Ready(Err(_))));
    assert!(matches!(replay.verify_complete(), Err(IoGroupCompletionError::Diverged(
        IoGroupReplayError::Stream { stream: 11, .. }
    ))));

    let replay = exchange(true).replay();
    let (_reader, mut writer) = replay.open(11).unwrap().into_split();
    assert!(matches!(Pin::new(&mut writer).poll_flush(&mut Context::from_waker(Waker::noop())), Poll::Ready(Err(_))));
    assert_eq!(replay.verify_complete(), Err(IoGroupCompletionError::Diverged(
        IoGroupReplayError::Operation { stream: 11, expected: IoOperation::Write, actual: IoOperation::Flush }
    )));
}

#[test]
fn vectored_flush_shutdown_and_recorded_eof_keep_exact_accounting() {
    let group = group();
    let mut io = group.register(7, Fixture::default()).unwrap();
    let bufs = [IoSlice::new(b"a"), IoSlice::new(b"bc")];
    let mut cx = Context::from_waker(Waker::noop());
    assert_eq!(value(Pin::new(&mut io).poll_write_vectored(&mut cx, &bufs)), 3);
    assert_eq!(value(read(&mut io, 4, Waker::noop())), b"");
    value(Pin::new(&mut io).poll_flush(&mut cx));
    value(Pin::new(&mut io).poll_shutdown(&mut cx));
    io.into_inner();
    let replay = group.finish().unwrap().replay();
    let (mut reader, mut writer) = replay.open(7).unwrap().into_split();
    assert!(writer.is_write_vectored());
    assert!(read(&mut reader, 4, Waker::noop()).is_pending());
    assert_eq!(value(Pin::new(&mut writer).poll_write_vectored(&mut cx, &bufs)), 3);
    assert!(Pin::new(&mut writer).poll_flush(&mut cx).is_pending());
    assert_eq!(value(read(&mut reader, 4, Waker::noop())), b"");
    value(Pin::new(&mut writer).poll_flush(&mut cx));
    value(Pin::new(&mut writer).poll_shutdown(&mut cx));
    replay.verify_complete().unwrap();
}

#[test]
fn original_io_error_consumes_read_observation_without_poisoning_write_half() {
    let group = group();
    let mut io = group.register(9, Fixture { read_error: true, ..Fixture::default() }).unwrap();
    assert!(matches!(read(&mut io, 2, Waker::noop()), Poll::Ready(Err(_))));
    value(write(&mut io, b"bye", Waker::noop()));
    io.into_inner();
    let replay = group.finish().unwrap().replay();
    let (mut reader, mut writer) = replay.open(9).unwrap().into_split();
    assert!(matches!(read(&mut reader, 2, Waker::noop()), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::ConnectionReset));
    drop(reader);
    value(write(&mut writer, b"bye", Waker::noop()));
    replay.verify_complete().unwrap();
}

#[test]
fn splitting_after_a_consumed_prefix_counts_only_remaining_observations() {
    let replay = exchange(true).replay();
    let mut io = replay.open(11).unwrap();
    value(write(&mut io, b"request", Waker::noop()));
    let (mut reader, writer) = io.into_split();
    drop(writer);
    assert_eq!(value(read(&mut reader, 5, Waker::noop())), b"reply");
    replay.verify_complete().unwrap();
}

#[test]
fn dropping_last_half_releases_shared_state_even_with_registered_group_waiter() {
    let replay = exchange(true).replay();
    let (mut reader, writer) = replay.open(11).unwrap().into_split();
    let weak = Arc::downgrade(&reader.shared);
    assert!(read(&mut reader, 5, Waker::noop()).is_pending());
    drop(reader); drop(writer);
    assert!(weak.upgrade().is_none(), "no group-to-halves ownership cycle");
    assert!(matches!(replay.verify_complete(), Err(IoGroupCompletionError::Diverged(_))));
}

#[test]
fn halves_are_send_sync_unpin_and_debug_excludes_payloads() {
    fn bounds<T: Send + Sync + Unpin>() {}
    bounds::<ReplayGroupReadHalf>();
    bounds::<ReplayGroupWriteHalf>();
    let replay = exchange(true).replay();
    let (reader, writer) = replay.open(11).unwrap().into_split();
    let debug = format!("{reader:?} {writer:?}");
    assert!(debug.contains("11"));
    assert!(!debug.contains("request"));
    assert!(!debug.contains("reply"));
}
