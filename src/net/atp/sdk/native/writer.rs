//! A bounded writable producer for a scope-owned native upload.
//!
//! Writes feed the existing disk-spooling uploader. Flush acknowledges completed
//! local spool writes, not remote delivery or crash durability. Shutdown sends
//! EOF and waits for the actual worker join, peer receipt, and local cleanup.
//! The manifest-first wire still starts only after EOF; this is not a live
//! unknown-length network stream.

use super::super::{NativeTransferClient, NativeTransferError};
use super::{
    MAX_UPLOAD_BUFFER, NativeUploadError, NativeUploadOptions, NativeUploadReport,
    NativeUploadTask, SpoolObserver, validate_upload,
};
use crate::cx::{Cx, Scope};
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::runtime::JoinError;
use crate::types::{CancelReason, Policy};
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

/// The retained canonical join and, when returned, the complete upload report.
///
/// Local cleanup failure does not erase a successful peer receipt. A runtime
/// rejection before execution can have a join error without an upload report.
pub type NativeUploadWriterTerminal = Result<NativeUploadReport, JoinError>;

#[derive(Debug, Default)]
struct InputState {
    bytes: VecDeque<u8>,
    accepted: u64,
    spooled: u64,
    high_water: usize,
    eof: bool,
    aborted: bool,
    reader_gone: bool,
    reader_waker: Option<Waker>,
    writer_waker: Option<Waker>,
}

#[derive(Debug)]
struct Input {
    capacity: usize,
    state: Mutex<InputState>,
}

// No user Waker clone/drop runs while the queue is locked. A missing incoming
// owner tells the caller to unlock, clone, and recheck the readiness predicate.
fn register(
    slot: &mut Option<Waker>,
    incoming: &mut Option<Waker>,
    current: &Waker,
) -> Option<Option<Waker>> {
    if slot.as_ref().is_some_and(|old| old.will_wake(current)) {
        Some(None)
    } else {
        incoming.take().map(|new| slot.replace(new))
    }
}

fn notify(waker: Option<Waker>) {
    if let Some(waker) = waker {
        waker.wake();
    }
}

fn closed_input() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "native upload input is closed")
}

impl Input {
    fn new(capacity: usize) -> Arc<Self> {
        assert!(capacity > 0, "native upload input capacity must be nonzero");
        Arc::new(Self { capacity, state: Mutex::new(InputState::default()) })
    }

    fn poll_write(&self, ctx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut incoming = None;
        loop {
            let mut state = self.state.lock();
            if state.aborted || state.eof || state.reader_gone {
                return Poll::Ready(Err(closed_input()));
            }
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let count = buf.len().min(self.capacity - state.bytes.len());
            if count != 0 {
                let Some(accepted) = state.accepted.checked_add(count as u64) else {
                    return Poll::Ready(Err(io::Error::other("upload byte counter exhausted")));
                };
                if let Err(error) = state.bytes.try_reserve(count) {
                    return Poll::Ready(Err(io::Error::other(error)));
                }
                state.bytes.extend(buf[..count].iter().copied());
                state.accepted = accepted;
                state.high_water = state.high_water.max(state.bytes.len());
                let wake = state.reader_waker.take();
                let retired = state.writer_waker.take();
                drop(state);
                notify(wake);
                drop(retired);
                return Poll::Ready(Ok(count));
            }
            if let Some(retired) = register(&mut state.writer_waker, &mut incoming, ctx.waker()) {
                drop(state);
                drop(retired);
                return Poll::Pending;
            }
            drop(state);
            incoming = Some(ctx.waker().clone());
        }
    }

    fn poll_flush(&self, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut incoming = None;
        loop {
            let mut state = self.state.lock();
            if state.aborted || state.reader_gone {
                return Poll::Ready(Err(closed_input()));
            }
            if state.spooled == state.accepted {
                let retired = state.writer_waker.take();
                drop(state);
                drop(retired);
                return Poll::Ready(Ok(()));
            }
            if let Some(retired) = register(&mut state.writer_waker, &mut incoming, ctx.waker()) {
                drop(state);
                drop(retired);
                return Poll::Pending;
            }
            drop(state);
            incoming = Some(ctx.waker().clone());
        }
    }

    // Return wake ownership so abort can publish the task's cancellation before
    // invoking any user-controlled wake callback.
    fn stop(&self, abort: bool) -> Option<Waker> {
        let mut state = self.state.lock();
        if abort {
            state.aborted = true;
            state.bytes.clear();
        } else {
            state.eof = true;
        }
        state.reader_waker.take()
    }
}

impl SpoolObserver for Input {
    fn on_spooled(&self, bytes: u64) {
        let wake = {
            let mut state = self.state.lock();
            debug_assert!(bytes >= state.spooled && bytes <= state.accepted);
            state.spooled = bytes;
            state.writer_waker.take()
        };
        notify(wake);
    }
}

struct InputReader(Arc<Input>);

impl AsyncRead for InputReader {
    fn poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut incoming = None;
        loop {
            let mut state = self.0.state.lock();
            if state.aborted {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Interrupted, "native upload producer aborted",
                )));
            }
            let count = buf.remaining().min(state.bytes.len());
            if count != 0 {
                let (first, second) = state.bytes.as_slices();
                let first_len = count.min(first.len());
                buf.put_slice(&first[..first_len]);
                buf.put_slice(&second[..count - first_len]);
                drop(state.bytes.drain(..count));
                let wake = state.writer_waker.take();
                let retired = state.reader_waker.take();
                drop(state);
                notify(wake);
                drop(retired);
                return Poll::Ready(Ok(()));
            }
            if state.eof {
                let retired = state.reader_waker.take();
                drop(state);
                drop(retired);
                return Poll::Ready(Ok(()));
            }
            if let Some(retired) = register(&mut state.reader_waker, &mut incoming, ctx.waker()) {
                drop(state);
                drop(retired);
                return Poll::Pending;
            }
            drop(state);
            incoming = Some(ctx.waker().clone());
        }
    }
}

impl Drop for InputReader {
    fn drop(&mut self) {
        let (wake, retired) = {
            let mut state = self.0.state.lock();
            state.reader_gone = true;
            state.bytes.clear();
            (state.writer_waker.take(), state.reader_waker.take())
        };
        notify(wake);
        drop(retired);
    }
}

/// Writable, bounded input plus the scope-owned upload worker that consumes it.
///
/// Successful writes acknowledge only the accepted prefix. A pending write
/// accepts nothing; dropping that write future cannot lose hidden read-ahead.
/// The queue holds at most `buffer_capacity()` unread bytes, in addition to the
/// uploader's separately bounded spool buffer and native transport buffers.
///
/// `flush` waits for actual completed local spool writes. `shutdown`/`finish`
/// closes input and waits for the canonical worker join, verified peer receipt,
/// and spool cleanup. Repeated finish calls retain the same terminal evidence.
/// Dropping this handle requests cancellation, never successful EOF; its owning
/// region still must drain the worker. No network retry is automatic.
#[derive(Debug)]
#[must_use = "finish or cancel_and_wait the upload; dropping requests cancellation, not delivery"]
pub struct NativeUploadWriter {
    input: Arc<Input>,
    worker: NativeUploadTask,
    terminal: Option<NativeUploadWriterTerminal>,
}

impl NativeTransferClient {
    /// Open bounded writable input and admit its uploader into `scope`.
    ///
    /// Capacity is reserved before the pipe or runtime request is allocated.
    /// The pipe byte capacity is the stricter native chunk size and 64 KiB.
    /// The worker receives its own child `Cx`, spools the producer's bytes, and
    /// starts the real native transfer only after explicit EOF. The configured
    /// source idle timeout also applies while the producer has nothing to write.
    ///
    /// # Errors
    /// Refuses invalid upload options, missing capabilities/TLS, exhausted
    /// transfer capacity, and immediate runtime admission failure. Deferred
    /// admission or transfer failures remain available through `finish`.
    pub fn open_writer<P: Policy>(
        &self,
        cx: &Cx,
        scope: &Scope<'_, P>,
        remote: SocketAddr,
        options: NativeUploadOptions,
    ) -> Result<NativeUploadWriter, NativeUploadError> {
        validate_upload(cx, &options)?;
        let admission = self.admit_sender()?;
        let input = Input::new(self.shared.config.chunk_size.min(MAX_UPLOAD_BUFFER));
        let reader = InputReader(Arc::clone(&input));
        let observer: Arc<dyn SpoolObserver> = input.clone();
        let worker = cx.spawn_in(scope, move |child| {
            let future: Pin<Box<dyn Future<Output = NativeUploadReport> + Send>> = Box::pin(async move {
                Self::upload_admitted(&child, remote, options, reader, admission, Some(observer)).await
            });
            future
        }).map_err(NativeTransferError::Spawn)?;
        Ok(NativeUploadWriter { input, worker, terminal: None })
    }
}

impl NativeUploadWriter {
    /// Maximum unread producer bytes in the queue (not the full transport RSS).
    #[must_use]
    pub fn buffer_capacity(&self) -> usize { self.input.capacity }

    /// Current unread producer bytes. This is not a delivery/completion signal.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize { self.input.state.lock().bytes.len() }

    /// Peak unread bytes retained in this pipe.
    #[must_use]
    pub fn buffer_high_water(&self) -> usize { self.input.state.lock().high_water }

    /// Total bytes accepted from successful write calls.
    #[must_use]
    pub fn accepted_bytes(&self) -> u64 { self.input.state.lock().accepted }

    /// Bytes acknowledged by completed local spool writes, not a peer receipt.
    #[must_use]
    pub fn spooled_bytes(&self) -> u64 { self.input.state.lock().spooled }

    /// Inspect retained terminal facts, collecting a ready join without blocking.
    /// This never consumes a report or interprets queue emptiness as completion.
    #[must_use]
    pub fn terminal(&mut self) -> Option<&NativeUploadWriterTerminal> {
        if self.terminal.is_none() {
            match self.worker.try_join() {
                Ok(None) => {}
                Ok(Some(report)) => self.settle(Ok(report)),
                Err(error) => self.settle(Err(error)),
            }
        }
        self.terminal.as_ref()
    }

    /// Stop accepting input and await the complete retained upload result.
    ///
    /// Dropping this wait leaves the writer, EOF, and worker ownership intact.
    /// A later call resumes waiting for the same canonical join.
    pub async fn finish(&mut self) -> &NativeUploadWriterTerminal {
        notify(self.input.stop(false));
        poll_fn(|ctx| self.poll_terminal(ctx)).await;
        self.terminal.as_ref().expect("joined native upload")
    }

    /// Request cancellation and await the worker, including its spool cleanup.
    ///
    /// Cancellation is cooperative. This wait does not abandon an in-flight OS
    /// write and cannot bound an OS operation or user poll that never returns.
    /// A transfer already underway may have published remotely; inspect the
    /// retained outcome and reconcile before retrying.
    pub async fn cancel_and_wait(&mut self, reason: CancelReason) -> &NativeUploadWriterTerminal {
        if self.terminal().is_none() {
            let wake = self.input.stop(true);
            self.worker.abort_with_reason(reason);
            notify(wake);
        }
        poll_fn(|ctx| self.poll_terminal(ctx)).await;
        self.terminal.as_ref().expect("joined native upload")
    }

    fn settle(&mut self, terminal: NativeUploadWriterTerminal) {
        self.terminal = Some(terminal);
        let retired = self.input.state.lock().writer_waker.take();
        drop(retired);
    }

    fn poll_terminal(&mut self, ctx: &mut Context<'_>) -> Poll<()> {
        if self.terminal.is_some() { return Poll::Ready(()); }
        match self.worker.poll_join(ctx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => { self.settle(result); Poll::Ready(()) }
        }
    }

    fn terminal_io_result(&self) -> io::Result<()> {
        match self.terminal.as_ref().expect("terminal join observed") {
            Err(JoinError::Cancelled(reason)) => Err(io::Error::new(
                io::ErrorKind::Interrupted, format!("upload worker cancelled: {reason}"),
            )),
            Err(error) => Err(io::Error::other(format!("upload worker failed: {error}"))),
            Ok(report) => {
                if let Err(error) = &report.outcome {
                    let kind = match error {
                        NativeUploadError::Cancelled { .. } => io::ErrorKind::Interrupted,
                        NativeUploadError::SourceTimeout => io::ErrorKind::TimedOut,
                        NativeUploadError::TooLarge { .. } => io::ErrorKind::InvalidInput,
                        NativeUploadError::Io(error) => error.kind(),
                        _ => io::ErrorKind::Other,
                    };
                    return Err(io::Error::new(kind, error.to_string()));
                }
                if let Some(cleanup) = &report.cleanup_error {
                    return Err(io::Error::new(cleanup.error.kind(), format!(
                        "peer receipt retained, but local upload cleanup failed: {}", cleanup.error,
                    )));
                }
                Ok(())
            }
        }
    }
}

impl AsyncWrite for NativeUploadWriter {
    fn poll_write(
        mut self: Pin<&mut Self>, ctx: &mut Context<'_>, buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Also register for deferred admission/worker failure, not only queue
        // space: the consumer may fail before ever polling its input reader.
        if self.poll_terminal(ctx).is_ready() {
            return Poll::Ready(self.terminal_io_result().and_then(|()| Err(closed_input())));
        }
        self.input.poll_write(ctx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.poll_terminal(ctx).is_ready() {
            return Poll::Ready(self.terminal_io_result());
        }
        self.input.poll_flush(ctx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        notify(self.input.stop(false));
        match self.poll_terminal(ctx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => Poll::Ready(self.terminal_io_result()),
        }
    }
}

impl Drop for NativeUploadWriter {
    fn drop(&mut self) {
        let wake = self.input.stop(true);
        if self.terminal.is_none() && !self.worker.is_finished() {
            self.worker.abort_with_reason(CancelReason::user("native upload writer dropped"));
        }
        notify(wake);
        let retired = self.input.state.lock().writer_waker.take();
        drop(retired);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    struct WakeCount(AtomicUsize);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
        fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    }
    fn counter() -> (Arc<WakeCount>, Waker) {
        let count = Arc::new(WakeCount(AtomicUsize::new(0)));
        (Arc::clone(&count), Waker::from(count))
    }
    fn read(reader: &mut InputReader, ctx: &mut Context<'_>, size: usize) -> Poll<io::Result<Vec<u8>>> {
        let mut storage = vec![0; size];
        let mut buf = ReadBuf::new(&mut storage);
        Pin::new(reader).poll_read(ctx, &mut buf).map(|result| result.map(|()| buf.filled().to_vec()))
    }
    fn ready<T: std::fmt::Debug>(poll: Poll<io::Result<T>>) -> T {
        match poll { Poll::Ready(Ok(value)) => value, other => panic!("expected success: {other:?}") }
    }

    #[test]
    fn full_input_parks_without_self_wakes_and_resumes_after_consumption() {
        let input = Input::new(3);
        let mut reader = InputReader(Arc::clone(&input));
        let (count, waker) = counter();
        let mut ctx = Context::from_waker(&waker);
        assert_eq!(ready(input.poll_write(&mut ctx, b"abcdef")), 3);
        for _ in 0..20 { assert!(input.poll_write(&mut ctx, b"def").is_pending()); }
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        assert_eq!(input.state.lock().accepted, 3, "pending writes accept nothing");
        assert_eq!(ready(read(&mut reader, &mut ctx, 2)), b"ab");
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert_eq!(ready(input.poll_write(&mut ctx, b"def")), 2);
        assert_eq!(ready(read(&mut reader, &mut ctx, 3)), b"cde");
        assert_eq!(input.state.lock().high_water, 3);
    }

    #[test]
    fn empty_input_waits_for_data_and_explicit_eof_drains_the_final_tail() {
        let input = Input::new(7);
        let mut reader = InputReader(Arc::clone(&input));
        let (count, waker) = counter();
        let mut ctx = Context::from_waker(&waker);
        assert!(read(&mut reader, &mut ctx, 3).is_pending());
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
        assert_eq!(ready(input.poll_write(&mut ctx, b"abcdefg")), 7);
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        notify(input.stop(false));
        assert_eq!(ready(read(&mut reader, &mut ctx, 3)), b"abc");
        assert_eq!(ready(read(&mut reader, &mut ctx, 3)), b"def");
        assert_eq!(ready(read(&mut reader, &mut ctx, 3)), b"g");
        assert!(ready(read(&mut reader, &mut ctx, 3)).is_empty());
        assert!(matches!(input.poll_write(&mut ctx, b"x"), Poll::Ready(Err(_))));
    }

    #[test]
    fn flush_requires_spool_acknowledgement_not_just_an_empty_pipe() {
        let input = Input::new(3);
        let mut reader = InputReader(Arc::clone(&input));
        let (count, waker) = counter();
        let mut ctx = Context::from_waker(&waker);
        ready(input.poll_write(&mut ctx, b"abc"));
        assert_eq!(ready(read(&mut reader, &mut ctx, 3)), b"abc");
        assert!(input.state.lock().bytes.is_empty());
        assert!(input.poll_flush(&mut ctx).is_pending());
        input.on_spooled(2);
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert!(input.poll_flush(&mut ctx).is_pending());
        input.on_spooled(3);
        ready(input.poll_flush(&mut ctx));
        assert_eq!(input.state.lock().spooled, 3);
    }

    #[test]
    fn abort_is_not_eof_and_reader_loss_wakes_a_full_producer() {
        let input = Input::new(1);
        let mut reader = InputReader(Arc::clone(&input));
        let (count, waker) = counter();
        let mut ctx = Context::from_waker(&waker);
        ready(input.poll_write(&mut ctx, b"x"));
        assert!(input.poll_write(&mut ctx, b"y").is_pending());
        drop(reader);
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert!(matches!(input.poll_write(&mut ctx, b"y"), Poll::Ready(Err(_))));

        let input = Input::new(1);
        reader = InputReader(Arc::clone(&input));
        assert!(read(&mut reader, &mut ctx, 1).is_pending());
        notify(input.stop(true));
        assert!(matches!(read(&mut reader, &mut ctx, 1),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted));
        assert!(matches!(input.poll_flush(&mut ctx), Poll::Ready(Err(_))));
    }

    #[test]
    fn queue_wraparound_preserves_every_byte_under_all_small_capacities() {
        for capacity in 1..17 {
            let input = Input::new(capacity);
            let mut reader = InputReader(Arc::clone(&input));
            let mut ctx = Context::from_waker(Waker::noop());
            let expected: Vec<u8> = (0u8..=255).cycle().take(4097).collect();
            let mut accepted = 0;
            let mut observed = Vec::new();
            while observed.len() < expected.len() {
                if accepted < expected.len() {
                    match input.poll_write(&mut ctx, &expected[accepted..]) {
                        Poll::Ready(Ok(n)) => accepted += n,
                        Poll::Pending => {}
                        other => panic!("unexpected write: {other:?}"),
                    }
                }
                if accepted == expected.len() { notify(input.stop(false)); }
                observed.extend(ready(read(&mut reader, &mut ctx, 3)));
                input.on_spooled(observed.len() as u64);
                assert!(input.state.lock().bytes.len() <= capacity);
            }
            ready(input.poll_flush(&mut ctx));
            assert_eq!(observed, expected);
            assert!(ready(read(&mut reader, &mut ctx, 1)).is_empty());
            assert!(input.state.lock().high_water <= capacity);
        }
    }
}
