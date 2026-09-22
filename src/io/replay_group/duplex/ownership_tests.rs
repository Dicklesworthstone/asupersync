//! Ownership and hostile-callback regressions; fixed byte fixtures, no network.
//! The threaded case proves this adapter's handoff, not native runtime cancellation.

use super::*;
use crate::io::replay::IoCaptureLimits;
use crate::io::replay_group::{
    IoGroupCaptureLimits, IoGroupCompletionError, IoRecordingGroup, RecordedIoGroup,
};
use std::sync::atomic::AtomicBool;

struct Source(&'static [u8]);
impl AsyncRead for Source {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let n = buf.remaining().min(this.0.len());
        buf.put_slice(&this.0[..n]);
        this.0 = &this.0[n..];
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Source {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
}
fn capture() -> IoRecordingGroup {
    IoRecordingGroup::new(IoGroupCaptureLimits {
        max_streams: 2,
        max_events: 16,
        per_stream: IoCaptureLimits::new(16, 128, 128, 8),
    })
}
fn read(io: &mut (impl AsyncRead + Unpin), waker: &Waker) -> Poll<io::Result<Vec<u8>>> {
    let mut bytes = [0; 5];
    let mut buf = ReadBuf::new(&mut bytes);
    let result = Pin::new(io).poll_read(&mut Context::from_waker(waker), &mut buf);
    result.map(|result| result.map(|()| buf.filled().to_vec()))
}
fn write(io: &mut (impl AsyncWrite + Unpin), waker: &Waker) -> Poll<io::Result<usize>> {
    Pin::new(io).poll_write(&mut Context::from_waker(waker), b"request")
}
fn value<T>(result: Poll<io::Result<T>>) -> T {
    match result { Poll::Ready(Ok(value)) => value, _ => panic!("expected recorded completion") }
}
fn tape(write_first: bool) -> RecordedIoGroup {
    let capture = capture();
    let mut stream = capture.register(21, Source(b"reply")).unwrap();
    if write_first { value(write(&mut stream, Waker::noop())); }
    assert_eq!(value(read(&mut stream, Waker::noop())), b"reply");
    if !write_first { value(write(&mut stream, Waker::noop())); }
    stream.into_inner();
    capture.finish().unwrap()
}
fn consume(stream: &mut ReplayGroupIo) {
    assert_eq!(value(write(stream, Waker::noop())), 7);
    assert_eq!(value(read(stream, Waker::noop())), b"reply");
}
#[derive(Default)]
struct Counter(AtomicUsize);
impl Wake for Counter {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

#[test]
fn reunite_preserves_unconsumed_tape_and_retires_pending_waiters_without_waking() {
    let replay = tape(true).replay();
    let (mut reader, writer) = replay.open(21).unwrap().into_split();
    let weak = Arc::downgrade(&reader.shared);
    let counter = Arc::new(Counter::default());
    let waker = Waker::from(Arc::clone(&counter));
    assert!(read(&mut reader, &waker).is_pending());
    let mut stream = reader.reunite(writer).unwrap();
    assert!(weak.upgrade().is_none());
    assert_eq!(counter.0.load(Ordering::SeqCst), 0);
    assert_eq!(replay.verify_complete(), Err(IoGroupCompletionError::Remaining(2)));
    consume(&mut stream);
    replay.verify_complete().unwrap();
}

#[test]
fn mismatched_groups_with_equal_stream_ids_return_both_original_halves_unchanged() {
    let a = tape(true).replay();
    let b = tape(true).replay();
    let (ra, wa) = a.open(21).unwrap().into_split();
    let (rb, wb) = b.open(21).unwrap().into_split();
    assert!(!ra.is_pair_of(&wb));
    let (ra, wb) = ra.reunite(wb).unwrap_err();
    assert!(ra.is_pair_of(&wa));
    assert!(rb.is_pair_of(&wb));
    assert_eq!(a.verify_complete(), Err(IoGroupCompletionError::Remaining(2)));
    assert_eq!(b.verify_complete(), Err(IoGroupCompletionError::Remaining(2)));
    consume(&mut ra.reunite(wa).unwrap());
    consume(&mut rb.reunite(wb).unwrap());
    a.verify_complete().unwrap();
    b.verify_complete().unwrap();
}

#[test]
fn reunite_and_resplit_after_prefix_preserve_directional_drop_accounting() {
    let replay = tape(true).replay();
    let (reader, mut writer) = replay.open(21).unwrap().into_split();
    value(write(&mut writer, Waker::noop()));
    let stream = reader.reunite(writer).unwrap();
    let (mut reader, writer) = stream.into_split();
    drop(writer);
    assert_eq!(value(read(&mut reader, Waker::noop())), b"reply");
    drop(reader);
    replay.verify_complete().unwrap();
}

#[test]
fn reunite_cannot_reset_a_sticky_divergence() {
    let replay = tape(true).replay();
    let (reader, mut writer) = replay.open(21).unwrap().into_split();
    let error = Pin::new(&mut writer).poll_write(&mut Context::from_waker(Waker::noop()), b"WRONG!!");
    assert!(matches!(error, Poll::Ready(Err(_))));
    let before = replay.verify_complete();
    assert!(matches!(before, Err(IoGroupCompletionError::Diverged(_))));
    let mut stream = reader.reunite(writer).unwrap();
    assert!(matches!(write(&mut stream, Waker::noop()), Poll::Ready(Err(_))));
    assert_eq!(replay.verify_complete(), before);
}

#[test]
fn reunited_stream_restores_strict_operation_order() {
    let replay = tape(true).replay();
    let (reader, writer) = replay.open(21).unwrap().into_split();
    let mut stream = reader.reunite(writer).unwrap();
    assert!(matches!(read(&mut stream, Waker::noop()), Poll::Ready(Err(_))));
    assert_eq!(replay.verify_complete(), Err(IoGroupCompletionError::Diverged(
        IoGroupReplayError::Operation { stream: 21, expected: IoOperation::Write, actual: IoOperation::Read }
    )));
}

#[test]
fn empty_stream_can_split_reunite_and_drop_without_inventing_operations() {
    let capture = capture();
    capture.register(21, Source(b"")).unwrap().into_inner();
    let replay = capture.finish().unwrap().replay();
    let (reader, writer) = replay.open(21).unwrap().into_split();
    let (reader, writer) = reader.reunite(writer).unwrap().into_split();
    drop(reader); drop(writer);
    replay.verify_complete().unwrap();
}

struct Reentrant {
    reader: Mutex<Option<ReplayGroupReadHalf>>,
    output: Mutex<Option<Vec<u8>>>,
    calls: AtomicUsize,
    failures: AtomicUsize,
}
impl Wake for Reentrant {
    fn wake(self: Arc<Self>) { self.wake_by_ref(); }
    fn wake_by_ref(self: &Arc<Self>) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let Some(mut owner) = self.reader.try_lock() else {
            self.failures.fetch_add(1, Ordering::SeqCst);
            return;
        };
        let waker = Waker::from(Arc::clone(self));
        match read(owner.as_mut().expect("reader retained during write"), &waker) {
            Poll::Ready(Ok(bytes)) => *self.output.lock() = Some(bytes),
            Poll::Ready(Err(_)) => { self.failures.fetch_add(1, Ordering::SeqCst); }
            Poll::Pending => {}
        }
    }
}

#[test]
fn synchronous_reentrant_wake_retries_after_exclusive_lease_is_restored() {
    let replay = tape(true).replay();
    let (reader, mut writer) = replay.open(21).unwrap().into_split();
    let reentrant = Arc::new(Reentrant {
        reader: Mutex::new(Some(reader)),
        output: Mutex::new(None),
        calls: AtomicUsize::new(0),
        failures: AtomicUsize::new(0),
    });
    let waker = Waker::from(Arc::clone(&reentrant));
    {
        let mut owner = reentrant.reader.lock();
        assert!(read(owner.as_mut().unwrap(), &waker).is_pending());
    }
    value(write(&mut writer, Waker::noop()));
    assert_eq!(reentrant.calls.load(Ordering::SeqCst), 2, "first wake contends; second has custody");
    assert_eq!(reentrant.failures.load(Ordering::SeqCst), 0);
    assert_eq!(*reentrant.output.lock(), Some(b"reply".to_vec()));
    let reader = reentrant.reader.lock().take().unwrap();
    drop(reader); drop(writer);
    replay.verify_complete().unwrap();
}

struct PanickingWake;
impl Wake for PanickingWake {
    fn wake(self: Arc<Self>) { panic!("deliberate callback sentinel"); }
}

#[test]
fn a_panicking_direction_waker_does_not_strand_the_other_direction() {
    let capture = capture();
    let mut gate = capture.register(99, Source(b"reply")).unwrap();
    let mut stream = capture.register(21, Source(b"reply")).unwrap();
    value(read(&mut gate, Waker::noop()));
    value(write(&mut stream, Waker::noop()));
    value(read(&mut stream, Waker::noop()));
    gate.into_inner(); stream.into_inner();
    let replay = capture.finish().unwrap().replay();
    let mut gate = replay.open(99).unwrap();
    let (mut reader, mut writer) = replay.open(21).unwrap().into_split();
    let counter = Arc::new(Counter::default());
    let write_waker = Waker::from(Arc::clone(&counter));
    assert!(read(&mut reader, &Waker::from(Arc::new(PanickingWake))).is_pending());
    assert!(write(&mut writer, &write_waker).is_pending());
    value(read(&mut gate, Waker::noop()));
    assert_eq!(counter.0.load(Ordering::SeqCst), 1);
    value(write(&mut writer, Waker::noop()));
    value(read(&mut reader, Waker::noop()));
    replay.verify_complete().unwrap();
}

struct DropAudit {
    shared: Weak<Shared>,
    drops: Arc<AtomicUsize>,
    locked: Arc<AtomicBool>,
}
impl Wake for DropAudit {
    fn wake(self: Arc<Self>) {}
}
impl Drop for DropAudit {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.upgrade() {
            if shared.state.try_lock().is_none() || shared.group.state.try_lock().is_none() {
                self.locked.store(true, Ordering::SeqCst);
            }
        }
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn replacing_a_pending_waiter_retires_its_callback_outside_both_locks() {
    let replay = tape(true).replay();
    let (mut reader, mut writer) = replay.open(21).unwrap().into_split();
    let drops = Arc::new(AtomicUsize::new(0));
    let locked = Arc::new(AtomicBool::new(false));
    let waker = Waker::from(Arc::new(DropAudit {
        shared: Arc::downgrade(&reader.shared),
        drops: Arc::clone(&drops),
        locked: Arc::clone(&locked),
    }));
    assert!(read(&mut reader, &waker).is_pending());
    drop(waker);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert!(read(&mut reader, Waker::noop()).is_pending());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(!locked.load(Ordering::SeqCst));
    value(write(&mut writer, Waker::noop()));
    value(read(&mut reader, Waker::noop()));
    replay.verify_complete().unwrap();
}

struct Signal(std::sync::mpsc::SyncSender<()>);
impl Wake for Signal {
    fn wake(self: Arc<Self>) { let _ = self.0.try_send(()); }
}

#[test]
fn parked_reader_on_another_thread_receives_its_write_prerequisite() {
    use std::sync::mpsc::sync_channel;
    use std::time::Duration;
    let replay = tape(true).replay();
    let (mut reader, mut writer) = replay.open(21).unwrap().into_split();
    let (ready_tx, ready_rx) = sync_channel(1);
    // Timeouts are watchdogs only; channel handshakes establish the ordering.
    std::thread::scope(|scope| {
        let child = scope.spawn(move || {
            let (wake_tx, wake_rx) = sync_channel(1);
            let waker = Waker::from(Arc::new(Signal(wake_tx)));
            assert!(read(&mut reader, &waker).is_pending());
            ready_tx.send(()).unwrap();
            // A first wake may arrive while the writer still owns its lease.
            // Pending then registers contention; restoration must wake us again.
            for _ in 0..3 {
                wake_rx.recv_timeout(Duration::from_secs(10)).expect("registered reader is woken");
                match read(&mut reader, &waker) {
                    Poll::Ready(Ok(bytes)) => {
                        assert_eq!(bytes, b"reply");
                        return reader;
                    }
                    Poll::Ready(Err(error)) => panic!("recorded read diverged: {error}"),
                    Poll::Pending => {}
                }
            }
            panic!("reader did not acquire the restored component lease");
        });
        ready_rx.recv_timeout(Duration::from_secs(10)).expect("reader registered before write");
        value(write(&mut writer, Waker::noop()));
        drop(child.join().expect("reader thread completes"));
    });
    drop(writer);
    replay.verify_complete().unwrap();
}

#[test]
fn abandoned_read_half_invalidates_and_wakes_a_parked_writer() {
    let replay = tape(false).replay();
    let (reader, mut writer) = replay.open(21).unwrap().into_split();
    let counter = Arc::new(Counter::default());
    let waker = Waker::from(Arc::clone(&counter));
    assert!(write(&mut writer, &waker).is_pending());
    drop(reader);
    assert_eq!(counter.0.load(Ordering::SeqCst), 1);
    assert!(matches!(write(&mut writer, &waker), Poll::Ready(Err(_))));
    assert_eq!(replay.verify_complete(), Err(IoGroupCompletionError::Diverged(
        IoGroupReplayError::AbandonedHalf { stream: 21, direction: ReplayDirection::Read, remaining: 1 }
    )));
}
