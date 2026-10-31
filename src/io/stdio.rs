//! Asynchronous handles to the process's standard input, output and error.
//!
//! The standard streams cannot be put in non-blocking mode without changing
//! them for every process that shares them, so each blocking call runs off
//! the async workers: on the runtime's blocking pool, or on a dedicated
//! thread when there is none. A read of standard input can wait
//! indefinitely, and a write can wait on a full pipe, without stalling other
//! tasks. A closed pool or failed thread creation returns an I/O error; a
//! standard-stream syscall never falls back to the async worker. A pending
//! pool read can delay the runtime's bounded blocking-pool shutdown until its
//! timeout, because the OS read itself cannot be interrupted.
//!
//! - [`Stdin`] reads in chunks. A read in flight belongs to the handle, so a
//!   cancelled `read` loses no input as long as the handle is kept: the next
//!   read returns those bytes. Dropping the handle while a read waits leaves
//!   that blocking read running until input arrives, and its bytes are lost;
//!   keep one `Stdin` for the life of the program.
//! - [`Stdout`] and [`Stderr`] write behind: `write` copies the bytes,
//!   starts the blocking write and returns. The next `write`, `flush` or
//!   `shutdown` waits for it and reports its error. Bytes accepted by
//!   `write` are written even if the handle is dropped first; `flush`
//!   before exiting to know they arrived. Admission refusal is reported by
//!   `write` before accepting any bytes, including when a configured pool
//!   queue or the bounded fallback thread capacity is full.
//!
//! Like the other I/O entry points that take no [`Cx`](crate::Cx), the
//! handles consult the calling task's context: a task whose context lacks
//! the IO capability is refused with `[ASUP-E009]`
//! ([`IoCapabilityDenied`](crate::cx::IoCapabilityDenied)).
//!
//! Each handle orders its own operations. Separate handles to one stream do
//! not coordinate, so concurrent writers can interleave chunks, as with
//! separate `std::io::stdout()` handles.
//!
//! ```no_run
//! use asupersync::io::{AsyncWriteExt, BufReader, Lines, stdin, stdout};
//! use asupersync::stream::StreamExt;
//!
//! # async fn echo() -> std::io::Result<()> {
//! let mut lines = Lines::new(BufReader::new(stdin()));
//! let mut out = stdout();
//! while let Some(line) = lines.next().await {
//!     out.write_all(line?.to_uppercase().as_bytes()).await?;
//!     out.write_all(b"\n").await?;
//! }
//! out.flush().await
//! # }
//! ```

use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::future::Future;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

/// The most bytes one blocking read or write moves.
const CHUNK_BYTES: usize = 64 * 1024;

type Blocking<T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send>>;

/// Runs `op` off the async workers: on the current runtime's blocking pool,
/// or on a dedicated thread outside a runtime or in one built without a pool.
fn off_worker<T, Op>(op: Op) -> Blocking<T>
where
    T: Send + 'static,
    Op: FnOnce() -> io::Result<T> + Send + 'static,
{
    let pool = crate::cx::Cx::current().and_then(|cx| cx.blocking_pool_handle_for_inheritance());
    Box::pin(crate::runtime::spawn_blocking::spawn_blocking_io_off_worker(pool, op))
}

/// An asynchronous handle to the process's standard input; see the
/// [module documentation](crate::io#in-memory-pipes-and-standard-streams).
pub struct Stdin {
    state: ReadState,
}

enum ReadState {
    Idle,
    Reading(Blocking<Vec<u8>>),
    /// Bytes read but not yet handed to a caller.
    Buffered {
        bytes: Vec<u8>,
        consumed: usize,
    },
}

/// An asynchronous handle to the process's standard input.
#[must_use]
pub fn stdin() -> Stdin {
    Stdin {
        state: ReadState::Idle,
    }
}

impl AsyncRead for Stdin {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                ReadState::Buffered { bytes, consumed } => {
                    let available = &bytes[*consumed..];
                    let take = available.len().min(buf.remaining());
                    buf.put_slice(&available[..take]);
                    *consumed += take;
                    if *consumed == bytes.len() {
                        this.state = ReadState::Idle;
                    }
                    return Poll::Ready(Ok(()));
                }
                ReadState::Idle => {
                    if buf.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    crate::cx::io_gate::require_ambient_io("io::stdin")?;
                    let len = buf.remaining().min(CHUNK_BYTES);
                    this.state = ReadState::Reading(off_worker(move || {
                        let mut bytes = vec![0_u8; len];
                        let read = io::stdin().lock().read(&mut bytes)?;
                        bytes.truncate(read);
                        Ok(bytes)
                    }));
                }
                ReadState::Reading(read) => match read.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => {
                        this.state = ReadState::Idle;
                        let bytes = result?;
                        if bytes.is_empty() {
                            // End of input.
                            return Poll::Ready(Ok(()));
                        }
                        this.state = ReadState::Buffered { bytes, consumed: 0 };
                    }
                },
            }
        }
    }
}

impl std::fmt::Debug for Stdin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad("Stdin { .. }")
    }
}

#[derive(Clone, Copy)]
enum Target {
    Stdout,
    Stderr,
}

impl Target {
    const fn operation(self) -> &'static str {
        match self {
            Self::Stdout => "io::stdout",
            Self::Stderr => "io::stderr",
        }
    }
}

/// The result slot of a write or flush running on the blocking pool.
#[derive(Default)]
struct Completion {
    state: parking_lot::Mutex<(Option<io::Result<()>>, Option<Waker>)>,
}

impl Completion {
    fn finish(&self, result: io::Result<()>) {
        let waker = {
            let mut state = self.state.lock();
            state.0 = Some(result);
            state.1.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn poll(&self, cx: &Context<'_>) -> Poll<io::Result<()>> {
        let mut incoming = None;
        loop {
            let mut state = self.state.lock();
            if let Some(result) = state.0.take() {
                let retired = state.1.take();
                drop(state);
                drop(retired);
                drop(incoming);
                return Poll::Ready(result);
            }
            if state
                .1
                .as_ref()
                .is_some_and(|waker| waker.will_wake(cx.waker()))
            {
                drop(state);
                drop(incoming);
                return Poll::Pending;
            }
            if let Some(incoming) = incoming.take() {
                let retired = state.1.replace(incoming);
                drop(state);
                drop(retired);
                return Poll::Pending;
            }
            // A custom clone can reenter or race completion. Recheck the
            // result after preparing the waker outside the mutex.
            drop(state);
            incoming = Some(cx.waker().clone());
        }
    }

    fn clear_waiter(&self) {
        let retired = self.state.lock().1.take();
        drop(retired);
    }
}

/// Finishes a [`Completion`] with an error when the pool drops its job
/// without running it (the pool is shutting down) or the job panics.
struct Unfinished(Option<Arc<Completion>>);

impl Drop for Unfinished {
    fn drop(&mut self) {
        if let Some(completion) = self.0.take() {
            completion.finish(Err(io::Error::other(
                "the standard stream operation did not complete: the blocking pool \
                 refused it or it panicked",
            )));
        }
    }
}

/// A write or flush in flight. It starts when it is created, and dropping it
/// does not cancel it, so bytes accepted by `write` are written even if the
/// handle is dropped first (br-asupersync-68jvck).
enum InFlight {
    /// On the runtime's blocking pool, which runs it whether or not anyone
    /// waits for the result.
    Pool(Arc<Completion>),
    /// On a dedicated thread, outside a runtime or in one without a pool.
    /// The thread has already started before this state is published.
    Thread(Blocking<()>),
}

impl InFlight {
    fn start<Op>(op: Op) -> io::Result<Self>
    where
        Op: FnOnce() -> io::Result<()> + Send + 'static,
    {
        if let Some(pool) =
            crate::cx::Cx::current().and_then(|cx| cx.blocking_pool_handle_for_inheritance())
        {
            let completion = Arc::new(Completion::default());
            let mut unfinished = Unfinished(Some(Arc::clone(&completion)));
            // The handle is not kept: dropping it does not cancel the job.
            let job = pool.try_spawn(move || {
                let result = op();
                if let Some(completion) = unfinished.0.take() {
                    completion.finish(result);
                }
            });
            if let Err(refused) = job {
                let kind = match refused.kind() {
                    crate::runtime::BlockingSpawnErrorKind::Saturated => io::ErrorKind::WouldBlock,
                    crate::runtime::BlockingSpawnErrorKind::Shutdown => io::ErrorKind::Other,
                };
                drop(refused);
                return Err(io::Error::new(
                    kind,
                    "the blocking pool refused the standard stream operation",
                ));
            }
            return Ok(Self::Pool(completion));
        }
        let thread = crate::runtime::spawn_blocking::try_spawn_blocking_io_on_thread(op)?;
        Ok(Self::Thread(Box::pin(thread)))
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Pool(completion) => completion.poll(cx),
            Self::Thread(thread) => thread.as_mut().poll(cx),
        }
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if let Self::Pool(completion) = self {
            // The committed write continues, but an abandoned wait must not
            // keep its caller alive through a blocked pool operation.
            completion.clear_waiter();
        }
    }
}

/// Write-behind state shared by [`Stdout`] and [`Stderr`].
struct Writer {
    target: Target,
    state: WriteState,
}

enum WriteState {
    Idle,
    Writing(InFlight),
    Flushing(InFlight),
}

impl Writer {
    const fn new(target: Target) -> Self {
        Self {
            target,
            state: WriteState::Idle,
        }
    }

    /// Waits for the operation in flight, if any, and returns its result.
    fn poll_settle(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let operation = match &mut self.state {
            WriteState::Idle => return Poll::Ready(Ok(())),
            WriteState::Writing(operation) | WriteState::Flushing(operation) => operation,
        };
        let result = std::task::ready!(operation.poll(cx));
        self.state = WriteState::Idle;
        Poll::Ready(result)
    }

    fn poll_write(&mut self, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        std::task::ready!(self.poll_settle(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let target = self.target;
        crate::cx::io_gate::require_ambient_io(target.operation())?;
        let chunk = data[..data.len().min(CHUNK_BYTES)].to_vec();
        let written = chunk.len();
        self.state = WriteState::Writing(InFlight::start(move || match target {
            Target::Stdout => io::stdout().lock().write_all(&chunk),
            Target::Stderr => io::stderr().lock().write_all(&chunk),
        })?);
        Poll::Ready(Ok(written))
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match &mut self.state {
                WriteState::Flushing(_) => return self.poll_settle(cx),
                WriteState::Writing(_) => std::task::ready!(self.poll_settle(cx))?,
                WriteState::Idle => {
                    let target = self.target;
                    crate::cx::io_gate::require_ambient_io(target.operation())?;
                    self.state = WriteState::Flushing(InFlight::start(move || match target {
                        Target::Stdout => io::stdout().lock().flush(),
                        Target::Stderr => io::stderr().lock().flush(),
                    })?);
                }
            }
        }
    }
}

macro_rules! output_handle {
    ($(#[$attr:meta])* $name:ident, $constructor:ident, $target:expr, $stream:literal) => {
        $(#[$attr])*
        pub struct $name {
            writer: Writer,
        }

        #[doc = concat!("An asynchronous handle to the process's standard ", $stream, ".")]
        #[must_use]
        pub fn $constructor() -> $name {
            $name {
                writer: Writer::new($target),
            }
        }

        impl AsyncWrite for $name {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                data: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.get_mut().writer.poll_write(cx, data)
            }

            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.get_mut().writer.poll_flush(cx)
            }

            fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.get_mut().writer.poll_flush(cx)
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.pad(concat!(stringify!($name), " { .. }"))
            }
        }
    };
}

output_handle!(
    /// An asynchronous handle to the process's standard output; see the
    /// [module documentation](crate::io#in-memory-pipes-and-standard-streams).
    Stdout,
    stdout,
    Target::Stdout,
    "output"
);

output_handle!(
    /// An asynchronous handle to the process's standard error; see the
    /// [module documentation](crate::io#in-memory-pipes-and-standard-streams).
    Stderr,
    stderr,
    Target::Stderr,
    "error"
);

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::Cx;
    use crate::io::AsyncReadExt;
    use crate::runtime::{
        BlockingAdmissionPolicy, BlockingPool, BlockingPoolOptions, BlockingQueuePolicy,
    };
    use futures_lite::future;
    use std::num::NonZeroUsize;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Weak, mpsc};
    use std::task::Wake;
    use std::time::Duration;

    const WAIT: Duration = Duration::from_secs(5);

    #[test]
    fn standard_stream_io_runs_off_worker_with_and_without_a_pool() {
        let pool = BlockingPool::new(1, 1);
        for context in [
            None,
            Some(Cx::for_testing()),
            Some(Cx::for_testing().with_blocking_pool_handle(Some(pool.handle()))),
        ] {
            let _ambient = Cx::set_current(context);
            let polling_thread = std::thread::current().id();
            let worker = future::block_on(off_worker(|| Ok(std::thread::current().id())))
                .expect("off-worker I/O result");
            assert_ne!(worker, polling_thread);
            let error = future::block_on(off_worker(|| {
                Err::<(), _>(io::Error::new(io::ErrorKind::NotFound, "I/O sentinel"))
            }))
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::NotFound);
        }
        assert!(pool.shutdown_and_wait(WAIT));
    }

    #[test]
    fn standard_stream_io_never_runs_inline_after_pool_shutdown() {
        let pool = BlockingPool::new(1, 1);
        let context = Cx::for_testing().with_blocking_pool_handle(Some(pool.handle()));
        assert!(pool.shutdown_and_wait(WAIT));
        let _ambient = Cx::set_current(Some(context));
        let calls = Arc::new(AtomicUsize::new(0));
        let called = Arc::clone(&calls);
        // This is the same bridge Stdin polls. A closed pool used to invoke
        // the closure here, potentially waiting for input on the async worker.
        let error = future::block_on(off_worker(move || {
            called.fetch_add(1, Ordering::SeqCst);
            Ok(23)
        }))
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let mut poll = Context::from_waker(Waker::noop());
        for target in [Target::Stdout, Target::Stderr] {
            let mut writer = Writer::new(target);
            assert!(matches!(
                writer.poll_write(&mut poll, b"refused before acceptance"),
                Poll::Ready(Err(_))
            ));
            assert!(matches!(writer.state, WriteState::Idle));
            assert!(matches!(writer.poll_flush(&mut poll), Poll::Ready(Err(_))));
        }
    }

    #[test]
    fn saturated_pool_writes_refuse_bytes_before_accepting_them() {
        let pool = BlockingPool::with_config_and_policies(
            1,
            1,
            BlockingPoolOptions::default(),
            BlockingQueuePolicy::Fifo,
            BlockingAdmissionPolicy::Bounded {
                max_queued: NonZeroUsize::new(1).unwrap(),
            },
        );
        let (entered, entry) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let running = pool
            .try_spawn(move || {
                entered.send(()).unwrap();
                gate.recv_timeout(WAIT).unwrap();
            })
            .unwrap();
        entry.recv_timeout(WAIT).unwrap();
        let queued = pool.try_spawn(|| {}).unwrap();
        assert_eq!(pool.pending_count(), 1);
        let _ambient = Cx::set_current(Some(
            Cx::for_testing().with_blocking_pool_handle(Some(pool.handle())),
        ));
        let mut poll = Context::from_waker(Waker::noop());
        for target in [Target::Stdout, Target::Stderr] {
            let mut writer = Writer::new(target);
            assert!(matches!(
                writer.poll_write(&mut poll, b"must never reach the stream"),
                Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WouldBlock
            ));
            assert!(matches!(writer.state, WriteState::Idle));
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let called = Arc::clone(&calls);
        assert!(
            InFlight::start(move || {
                called.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .is_err()
        );
        release.send(()).unwrap();
        assert!(running.wait_timeout(WAIT));
        assert!(queued.wait_timeout(WAIT));
        assert!(pool.shutdown_and_wait(WAIT));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn cancelled_read_wait_preserves_the_handles_in_flight_bytes() {
        for with_pool in [false, true] {
            let pool = BlockingPool::new(1, 1);
            let context =
                Cx::for_testing().with_blocking_pool_handle(with_pool.then(|| pool.handle()));
            let _ambient = Cx::set_current(Some(context));
            let (entered, entry) = mpsc::channel();
            let (release, gate) = mpsc::channel();
            let mut input = Stdin {
                state: ReadState::Reading(off_worker(move || {
                    entered.send(()).unwrap();
                    gate.recv_timeout(WAIT).unwrap();
                    Ok(b"abcdef".to_vec())
                })),
            };
            let mut first = [0; 3];
            {
                let mut read = Box::pin(input.read(&mut first));
                assert!(
                    read.as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
                entry.recv_timeout(WAIT).unwrap();
                // Drop only this borrowing read, retaining Stdin's operation.
            }
            release.send(()).unwrap();
            future::block_on(input.read_exact(&mut first)).unwrap();
            let mut rest = [0; 3];
            future::block_on(input.read_exact(&mut rest)).unwrap();
            assert_eq!(&first, b"abc");
            assert_eq!(&rest, b"def");
            assert!(pool.shutdown_and_wait(WAIT));
        }
    }

    #[test]
    fn accepted_thread_write_runs_even_when_its_unpolled_handle_is_dropped() {
        let _ambient = Cx::set_current(None);
        let (entered, entry) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let (finished, finish) = mpsc::channel();
        let operation = InFlight::start(move || {
            entered.send(std::thread::current().id()).unwrap();
            gate.recv_timeout(WAIT).unwrap();
            finished.send(()).unwrap();
            Ok(())
        })
        .unwrap_or_else(|error| panic!("start committed write: {error}"));
        let worker = entry.recv_timeout(WAIT).unwrap();
        assert_ne!(worker, std::thread::current().id());
        // The I/O thread already owns the work. No future poll is necessary
        // for acceptance, and abandonment parks its handle instead of detaching.
        drop(operation);
        assert_eq!(
            crate::runtime::spawn_blocking::parked_thread(worker),
            Some(false)
        );
        release.send(()).unwrap();
        finish.recv_timeout(WAIT).unwrap();
    }

    #[test]
    fn accepted_pool_write_survives_drop_while_still_queued() {
        let pool = BlockingPool::new(1, 1);
        let (entered, entry) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let running = pool.spawn(move || {
            entered.send(()).unwrap();
            gate.recv_timeout(WAIT).unwrap();
        });
        entry.recv_timeout(WAIT).unwrap();
        let _ambient = Cx::set_current(Some(
            Cx::for_testing().with_blocking_pool_handle(Some(pool.handle())),
        ));
        let (finished, finish) = mpsc::channel();
        let operation = InFlight::start(move || {
            finished.send(()).unwrap();
            Ok(())
        })
        .unwrap_or_else(|error| panic!("queue committed write: {error}"));
        assert_eq!(pool.pending_count(), 1);
        drop(operation);
        release.send(()).unwrap();
        finish.recv_timeout(WAIT).unwrap();
        assert!(running.wait_timeout(WAIT));
        assert!(pool.shutdown_and_wait(WAIT));
    }

    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct FinishOnDrop(Weak<Completion>);

    impl Wake for FinishOnDrop {
        fn wake(self: Arc<Self>) {}
    }

    impl Drop for FinishOnDrop {
        fn drop(&mut self) {
            let completion = self.0.upgrade().unwrap();
            assert!(completion.state.try_lock().is_some(), "drop outside gate");
            completion.finish(Ok(()));
        }
    }

    #[test]
    fn replaced_stdio_waiter_may_complete_the_operation_reentrantly() {
        let completion = Arc::new(Completion::default());
        let original = Waker::from(Arc::new(FinishOnDrop(Arc::downgrade(&completion))));
        assert!(
            completion
                .poll(&Context::from_waker(&original))
                .is_pending()
        );
        drop(original);
        let calls = Arc::new(WakeCount(AtomicUsize::new(0)));
        let replacement = Waker::from(Arc::clone(&calls));
        let context = Context::from_waker(&replacement);
        assert!(completion.poll(&context).is_pending());
        assert_eq!(calls.0.load(Ordering::SeqCst), 1);
        assert!(matches!(completion.poll(&context), Poll::Ready(Ok(()))));
    }

    #[test]
    fn abandoned_stdio_waiter_does_not_keep_its_task_alive() {
        let completion = Arc::new(Completion::default());
        let task = Arc::new(WakeCount(AtomicUsize::new(0)));
        let weak = Arc::downgrade(&task);
        let waker = Waker::from(task);
        assert!(completion.poll(&Context::from_waker(&waker)).is_pending());
        drop(waker);
        let operation = InFlight::Pool(Arc::clone(&completion));
        drop(operation);
        assert!(weak.upgrade().is_none());
        completion.finish(Ok(()));
        assert!(matches!(
            completion.poll(&Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(()))
        ));
    }
}
