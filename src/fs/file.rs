//! Async file implementation.
//!
//! This module provides async filesystem I/O by running blocking operations
//! on a background thread via `spawn_blocking_io`. The file handle is wrapped
//! in `Arc` to allow sharing across the async boundary. Cursor-using operations
//! also share a gate that remains held until a started blocking syscall
//! completes, even if the awaiting future is dropped.
//!
//! The owned async methods offload filesystem calls through the runtime
//! blocking-I/O path. The poll-based traits (`AsyncRead`, `AsyncWrite`,
//! `AsyncSeek`) offload through the same path: each poll submits one bounded
//! syscall to the blocking pool and returns `Pending` until it completes, so
//! `BufReader<File>` and friends no longer stall the async worker. Regular
//! files expose no portable readiness notification, which is why the trait
//! path is a blocking-pool state machine rather than a reactor registration.
//! On a runtime built without a blocking pool (`blocking_threads(0, 0)`, the
//! bare `RuntimeBuilder` default) the offload degrades to the deterministic
//! inline fallback of `spawn_blocking`, which is the pre-existing behaviour.

#![allow(clippy::unused_async)]

use crate::fs::OpenOptions;
use crate::fs::metadata::{Metadata, Permissions};
use crate::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};
use crate::runtime::spawn_blocking_io;
use parking_lot::Mutex;
use std::fmt;
use std::future::Future;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
#[cfg(feature = "test-internals")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "test-internals")]
use std::sync::{Condvar, Mutex as StdMutex};
use std::task::{Context, Poll};
#[cfg(feature = "test-internals")]
use std::time::Duration;

/// Deterministic handshake for testing started cursor operations.
///
/// This is a test-only API. The first cursor operation installed with this
/// probe pauses after acquiring the cursor gate and before invoking its file
/// syscall. Tests can then drop the operation's future and start a replacement
/// operation while proving that the replacement has reached, but not passed,
/// the same gate.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
#[derive(Debug)]
pub struct FileCursorOperationProbe {
    block_first: AtomicBool,
    arrivals: StdMutex<usize>,
    arrivals_cv: Condvar,
    acquisitions: StdMutex<usize>,
    first_blocked: StdMutex<bool>,
    first_blocked_cv: Condvar,
    release_first: StdMutex<bool>,
    release_first_cv: Condvar,
}

#[cfg(feature = "test-internals")]
impl FileCursorOperationProbe {
    /// Creates a probe armed to pause the first cursor operation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            block_first: AtomicBool::new(true),
            arrivals: StdMutex::new(0),
            arrivals_cv: Condvar::new(),
            acquisitions: StdMutex::new(0),
            first_blocked: StdMutex::new(false),
            first_blocked_cv: Condvar::new(),
            release_first: StdMutex::new(false),
            release_first_cv: Condvar::new(),
        }
    }

    fn before_gate(&self) {
        let mut arrivals = self
            .arrivals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *arrivals += 1;
        self.arrivals_cv.notify_all();
    }

    fn after_gate(&self) {
        {
            let mut acquisitions = self
                .acquisitions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *acquisitions += 1;
        }

        if !self.block_first.swap(false, Ordering::AcqRel) {
            return;
        }

        {
            let mut first_blocked = self
                .first_blocked
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *first_blocked = true;
            self.first_blocked_cv.notify_all();
        }

        let release = self
            .release_first
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        drop(
            self.release_first_cv
                .wait_while(release, |released| !*released)
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
    }

    /// Waits until the first cursor operation owns the cursor gate.
    #[must_use]
    pub fn wait_until_first_blocked(&self, timeout: Duration) -> bool {
        let first_blocked = self
            .first_blocked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (first_blocked, _) = self
            .first_blocked_cv
            .wait_timeout_while(first_blocked, timeout, |blocked| !*blocked)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *first_blocked
    }

    /// Waits until at least `expected` cursor operations have reached the gate.
    #[must_use]
    pub fn wait_for_arrivals(&self, expected: usize, timeout: Duration) -> bool {
        let arrivals = self
            .arrivals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (arrivals, _) = self
            .arrivals_cv
            .wait_timeout_while(arrivals, timeout, |arrivals| *arrivals < expected)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *arrivals >= expected
    }

    /// Returns the number of operations that have acquired the cursor gate.
    #[must_use]
    pub fn acquisition_count(&self) -> usize {
        *self
            .acquisitions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Releases the first cursor operation.
    pub fn release_first(&self) {
        let mut release = self
            .release_first
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *release = true;
        self.release_first_cv.notify_all();
    }
}

#[cfg(feature = "test-internals")]
impl Default for FileCursorOperationProbe {
    fn default() -> Self {
        Self::new()
    }
}

/// Largest single syscall the poll-trait path submits to the blocking pool.
///
/// Bounding the chunk keeps each pool hop's buffer allocation small and lets
/// the async worker interleave other tasks between hops of a large transfer.
const POLL_IO_CHUNK_BYTES: usize = 128 * 1024;

type PollIoFuture<T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send>>;

/// In-flight blocking-pool operation behind the poll-based traits.
///
/// Exactly one operation is outstanding per handle at a time; the trait
/// contracts already require callers to retry the same operation until it
/// completes.
enum PendingIo {
    Read {
        future: PollIoFuture<Vec<u8>>,
    },
    /// Bytes read by a completed syscall that did not fit the caller's buffer
    /// on the poll that observed completion.
    ReadAhead {
        bytes: Vec<u8>,
        consumed: usize,
    },
    Write {
        future: PollIoFuture<usize>,
    },
    Flush {
        future: PollIoFuture<()>,
    },
    Seek {
        future: PollIoFuture<u64>,
    },
}

impl fmt::Debug for PendingIo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { .. } => f.write_str("PendingIo::Read"),
            Self::ReadAhead { bytes, consumed } => f
                .debug_struct("PendingIo::ReadAhead")
                .field("remaining", &(bytes.len() - consumed))
                .finish(),
            Self::Write { .. } => f.write_str("PendingIo::Write"),
            Self::Flush { .. } => f.write_str("PendingIo::Flush"),
            Self::Seek { .. } => f.write_str("PendingIo::Seek"),
        }
    }
}

/// An open file on the filesystem.
///
/// The file handle is wrapped in `Arc` to allow sharing across
/// `spawn_blocking_io` boundaries for async operations.
pub struct File {
    pub(crate) inner: Arc<std::fs::File>,
    cursor_gate: Arc<Mutex<()>>,
    /// Outstanding blocking-pool operation of the poll-based traits.
    pending: Mutex<Option<PendingIo>>,
    #[cfg(feature = "test-internals")]
    cursor_probe: Option<Arc<FileCursorOperationProbe>>,
}

impl fmt::Debug for File {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("File");
        debug.field("inner", &self.inner);
        debug.field("pending", &*self.pending.lock());
        #[cfg(feature = "test-internals")]
        debug.field("cursor_probe", &self.cursor_probe);
        debug.finish_non_exhaustive()
    }
}

impl File {
    async fn with_inner<R, F>(&self, op: F) -> io::Result<R>
    where
        R: Send + 'static,
        F: FnOnce(Arc<std::fs::File>) -> io::Result<R> + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        spawn_blocking_io(move || op(inner)).await
    }

    async fn with_cursor_inner<R, F>(&self, op: F) -> io::Result<R>
    where
        R: Send + 'static,
        F: FnOnce(Arc<std::fs::File>) -> io::Result<R> + Send + 'static,
    {
        // The poll-based traits may have a syscall in flight or read-ahead
        // bytes the caller never consumed; both move the OS cursor past where
        // the caller believes it is. Settle them first so this owned cursor
        // operation observes the caller's cursor.
        let rewind = self.settle_trait_pending().await?;
        let inner = Arc::clone(&self.inner);
        let cursor_gate = Arc::clone(&self.cursor_gate);
        #[cfg(feature = "test-internals")]
        let cursor_probe = self.cursor_probe.clone();

        spawn_blocking_io(move || {
            #[cfg(feature = "test-internals")]
            if let Some(probe) = &cursor_probe {
                probe.before_gate();
            }

            let _cursor_guard = cursor_gate.lock();

            #[cfg(feature = "test-internals")]
            if let Some(probe) = &cursor_probe {
                probe.after_gate();
            }

            if rewind != 0 {
                let mut file_ref: &std::fs::File = &inner;
                Seek::seek(&mut file_ref, SeekFrom::Current(-rewind))?;
            }
            op(inner)
        })
        .await
    }

    /// Opens a file in read-only mode.
    ///
    /// See [`OpenOptions::open`] for more options.
    pub async fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_owned();
        let file = spawn_blocking_io(move || std::fs::File::open(&path)).await?;
        Ok(Self::from_std(file))
    }

    /// Opens a file in write-only mode.
    ///
    /// This function will create a file if it does not exist, and will truncate it if it does.
    /// A started open may create or truncate the path after cancellation.
    pub async fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_owned();
        let file = spawn_blocking_io(move || std::fs::File::create(&path)).await?;
        Ok(Self::from_std(file))
    }

    /// Opens a file in read-write mode, failing if it already exists.
    ///
    /// The create-new operation is atomic with respect to other filesystem
    /// creators. If this succeeds, the returned file is guaranteed to be new.
    /// A started creation may still commit after the future is dropped.
    pub async fn create_new(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_owned();
        let file = spawn_blocking_io(move || {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
        })
        .await?;
        Ok(Self::from_std(file))
    }

    /// Returns a new `OpenOptions` object.
    #[must_use]
    pub fn options() -> OpenOptions {
        OpenOptions::new()
    }

    /// Creates an async `File` from a standard library file handle.
    ///
    /// This establishes a new cursor-synchronization domain. If independently
    /// duplicated standard handles share an OS cursor, wrap one handle and use
    /// [`File::try_clone`] so all async wrappers share the same cursor gate.
    #[must_use]
    pub fn from_std(file: std::fs::File) -> Self {
        Self {
            inner: Arc::new(file),
            cursor_gate: Arc::new(Mutex::new(())),
            pending: Mutex::new(None),
            #[cfg(feature = "test-internals")]
            cursor_probe: None,
        }
    }

    /// Consumes this wrapper and returns a standard library file handle.
    ///
    /// If the underlying handle is shared, this returns a cloned handle. This
    /// waits for any started cursor operation in this wrapper family before the
    /// standard handle escapes; later standard-handle access is outside the
    /// async wrapper's cursor gate.
    pub fn into_std(self) -> io::Result<std::fs::File> {
        let Self {
            inner,
            cursor_gate,
            pending: _,
            #[cfg(feature = "test-internals")]
                cursor_probe: _,
        } = self;
        let _cursor_guard = cursor_gate.lock();
        match Arc::try_unwrap(inner) {
            Ok(file) => Ok(file),
            Err(shared) => shared.try_clone(),
        }
    }

    /// Attempts to sync all OS-internal metadata to disk.
    ///
    /// A started sync may finish after the returned future is dropped.
    pub async fn sync_all(&self) -> io::Result<()> {
        self.with_inner(|inner| inner.sync_all()).await
    }

    /// This function is similar to `sync_all`, except that it will not sync file metadata.
    /// A started sync may finish after the returned future is dropped.
    pub async fn sync_data(&self) -> io::Result<()> {
        self.with_inner(|inner| inner.sync_data()).await
    }

    /// Truncates or extends the underlying file.
    ///
    /// This uses soft cancellation. A started resize may commit after the
    /// returned future is dropped.
    pub async fn set_len(&self, size: u64) -> io::Result<()> {
        self.with_inner(move |inner| inner.set_len(size)).await
    }

    /// Queries metadata about the underlying file.
    pub async fn metadata(&self) -> io::Result<Metadata> {
        self.with_inner(|inner| inner.metadata())
            .await
            .map(Metadata::from_std)
    }

    /// Creates a new `File` instance that shares the same underlying file handle
    /// and cursor completion gate.
    pub async fn try_clone(&self) -> io::Result<Self> {
        let file = self.with_inner(|inner| inner.try_clone()).await?;
        Ok(Self {
            inner: Arc::new(file),
            cursor_gate: Arc::clone(&self.cursor_gate),
            pending: Mutex::new(None),
            #[cfg(feature = "test-internals")]
            cursor_probe: self.cursor_probe.clone(),
        })
    }

    /// Changes the permissions on the underlying file.
    ///
    /// This uses soft cancellation. A started permission change may commit
    /// after the returned future is dropped.
    pub async fn set_permissions(&self, perm: Permissions) -> io::Result<()> {
        self.with_inner(move |inner| inner.set_permissions(perm.into_inner()))
            .await
    }

    // Helper methods that match std::fs::File but async.
    // Note: These require &mut self because they use the shared file cursor.
    // A started operation uses soft cancellation: dropping its future discards
    // its result but does not stop its syscall. The shared cursor gate keeps a
    // later operation from overtaking that completion. Cloned wrappers share
    // both the OS offset and the same gate.

    /// Moves the shared file cursor and returns the new position.
    ///
    /// If this future is dropped after the syscall starts, the seek may still
    /// complete. A later cursor operation waits for that completion.
    pub async fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.with_cursor_inner(move |inner| {
            let mut inner_ref: &std::fs::File = &inner;
            Seek::seek(&mut inner_ref, pos)
        })
        .await
    }

    /// Gets the current stream position.
    pub async fn stream_position(&mut self) -> io::Result<u64> {
        self.with_cursor_inner(move |inner| {
            let mut inner_ref: &std::fs::File = &inner;
            Seek::stream_position(&mut inner_ref)
        })
        .await
    }

    /// Rewinds the stream to the beginning.
    ///
    /// If this future is dropped after the syscall starts, the rewind may still
    /// complete. A later cursor operation waits for that completion.
    pub async fn rewind(&mut self) -> io::Result<()> {
        self.with_cursor_inner(move |inner| {
            let mut inner_ref: &std::fs::File = &inner;
            Seek::rewind(&mut inner_ref)
        })
        .await
    }

    /// Reads into an owned buffer on the blocking I/O pool.
    ///
    /// The returned buffer is the same allocation passed by the caller, allowing
    /// chunked readers to reuse a single allocation across async boundaries.
    /// If this future is dropped after the read starts, the read and its cursor
    /// advance may still complete and the owned buffer is discarded. A later
    /// cursor operation waits for that completion before accessing the file.
    pub async fn read_into_vec(&mut self, mut buf: Vec<u8>) -> io::Result<(Vec<u8>, usize)> {
        self.with_cursor_inner(move |inner| {
            let mut inner_ref: &std::fs::File = &inner;
            let bytes_read = Read::read(&mut inner_ref, buf.as_mut_slice())?;
            Ok((buf, bytes_read))
        })
        .await
    }

    /// Installs a one-shot cursor-operation handshake for deterministic tests.
    #[cfg(feature = "test-internals")]
    #[doc(hidden)]
    pub fn install_cursor_operation_probe_for_test(
        &mut self,
        probe: Arc<FileCursorOperationProbe>,
    ) {
        self.cursor_probe = Some(probe);
    }
}

// Phase 0: Poll-based traits use direct blocking I/O against the underlying
// std::fs::File. Shared handles inherit the platform's shared-cursor semantics
// and use the same gate as the owned cursor operations.

impl File {
    /// Submits one bounded blocking syscall to the runtime blocking pool on
    /// behalf of a poll-trait call. The cursor gate is taken inside the
    /// closure so a started syscall keeps the gate until it completes, exactly
    /// like the owned async methods.
    fn submit_blocking<T, Op>(&self, op: Op) -> PollIoFuture<T>
    where
        T: Send + 'static,
        Op: FnOnce(&std::fs::File) -> io::Result<T> + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        let cursor_gate = Arc::clone(&self.cursor_gate);
        Box::pin(spawn_blocking_io(move || {
            let _cursor_guard = cursor_gate.lock();
            op(&inner)
        }))
    }

    /// Drives an outstanding operation that belongs to a *different* trait
    /// call (for example a write whose future the caller dropped mid-flight)
    /// to a settled state before a new operation starts, so no started
    /// syscall is ever lost or reordered. A completed read settles as
    /// read-ahead bytes; a completed write, flush, or seek settles as `None`.
    fn settle_foreign_pending(
        pending: &mut Option<PendingIo>,
        poll_cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match pending.take() {
            None => Poll::Ready(Ok(())),
            Some(read_ahead @ PendingIo::ReadAhead { .. }) => {
                *pending = Some(read_ahead);
                Poll::Ready(Ok(()))
            }
            Some(PendingIo::Read { mut future }) => match future.as_mut().poll(poll_cx) {
                Poll::Pending => {
                    *pending = Some(PendingIo::Read { future });
                    Poll::Pending
                }
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(bytes)) => {
                    if !bytes.is_empty() {
                        *pending = Some(PendingIo::ReadAhead { bytes, consumed: 0 });
                    }
                    Poll::Ready(Ok(()))
                }
            },
            Some(PendingIo::Write { mut future }) => match future.as_mut().poll(poll_cx) {
                Poll::Pending => {
                    *pending = Some(PendingIo::Write { future });
                    Poll::Pending
                }
                // The abandoned write's byte count has no consumer left; the
                // bytes were committed to the file, which is the documented
                // "started syscall commits" behaviour.
                Poll::Ready(result) => Poll::Ready(result.map(|_| ())),
            },
            Some(PendingIo::Flush { mut future }) => match future.as_mut().poll(poll_cx) {
                Poll::Pending => {
                    *pending = Some(PendingIo::Flush { future });
                    Poll::Pending
                }
                Poll::Ready(result) => Poll::Ready(result),
            },
            Some(PendingIo::Seek { mut future }) => match future.as_mut().poll(poll_cx) {
                Poll::Pending => {
                    *pending = Some(PendingIo::Seek { future });
                    Poll::Pending
                }
                Poll::Ready(result) => Poll::Ready(result.map(|_| ())),
            },
        }
    }

    /// Number of read-ahead bytes the OS cursor is already past but the
    /// caller has not consumed. Writes and relative seeks compensate for it.
    fn unconsumed_read_ahead(pending: &Option<PendingIo>) -> usize {
        match pending {
            Some(PendingIo::ReadAhead { bytes, consumed }) => bytes.len() - consumed,
            _ => 0,
        }
    }

    /// Waits for any in-flight poll-trait syscall, discards unconsumed
    /// read-ahead, and returns how many bytes the OS cursor must be rewound
    /// so the next owned cursor operation starts where the caller believes
    /// the cursor is.
    async fn settle_trait_pending(&self) -> io::Result<i64> {
        std::future::poll_fn(|poll_cx| {
            let mut pending = self.pending.lock();
            match Self::settle_foreign_pending(&mut pending, poll_cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let unconsumed = Self::unconsumed_read_ahead(&pending);
                    *pending = None;
                    Poll::Ready(
                        i64::try_from(unconsumed)
                            .map_err(|_| io::Error::other("read-ahead exceeds seek range")),
                    )
                }
            }
        })
        .await
    }
}

impl AsyncRead for File {
    fn poll_read(
        self: Pin<&mut Self>,
        poll_cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        let mut pending = this.pending.lock();
        loop {
            match pending.take() {
                None => {
                    let len = buf.remaining().min(POLL_IO_CHUNK_BYTES);
                    let future = this.submit_blocking(move |file| {
                        let mut bytes = vec![0u8; len];
                        let mut file_ref: &std::fs::File = file;
                        let read = Read::read(&mut file_ref, &mut bytes)?;
                        bytes.truncate(read);
                        Ok(bytes)
                    });
                    *pending = Some(PendingIo::Read { future });
                }
                Some(PendingIo::Read { mut future }) => match future.as_mut().poll(poll_cx) {
                    Poll::Pending => {
                        *pending = Some(PendingIo::Read { future });
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(bytes)) => {
                        if bytes.is_empty() {
                            // End of file: nothing to hand over, nothing pending.
                            return Poll::Ready(Ok(()));
                        }
                        *pending = Some(PendingIo::ReadAhead { bytes, consumed: 0 });
                    }
                },
                Some(PendingIo::ReadAhead { bytes, consumed }) => {
                    let available = &bytes[consumed..];
                    let take = available.len().min(buf.remaining());
                    buf.unfilled()[..take].copy_from_slice(&available[..take]);
                    buf.advance(take);
                    let consumed = consumed + take;
                    if consumed < bytes.len() {
                        *pending = Some(PendingIo::ReadAhead { bytes, consumed });
                    }
                    return Poll::Ready(Ok(()));
                }
                other => {
                    *pending = other;
                    match Self::settle_foreign_pending(&mut pending, poll_cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {}
                    }
                }
            }
        }
    }
}

impl AsyncWrite for File {
    fn poll_write(
        self: Pin<&mut Self>,
        poll_cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        let mut pending = this.pending.lock();
        loop {
            match pending.take() {
                Some(PendingIo::Write { mut future }) => match future.as_mut().poll(poll_cx) {
                    Poll::Pending => {
                        *pending = Some(PendingIo::Write { future });
                        return Poll::Pending;
                    }
                    Poll::Ready(result) => return Poll::Ready(result),
                },
                None => {
                    // The trait contract requires callers to retry with the
                    // same bytes until `Ready`, so the chunk is copied once and
                    // the count of that chunk is reported on completion.
                    let chunk = buf[..buf.len().min(POLL_IO_CHUNK_BYTES)].to_vec();
                    let future = this.submit_blocking(move |file| {
                        let mut file_ref: &std::fs::File = file;
                        Write::write(&mut file_ref, &chunk)
                    });
                    *pending = Some(PendingIo::Write { future });
                }
                Some(PendingIo::ReadAhead { bytes, consumed }) => {
                    // The OS cursor sits past bytes the caller never consumed;
                    // rewind before writing so the write lands where the
                    // caller believes the cursor is.
                    let rewind = i64::try_from(bytes.len() - consumed)
                        .map_err(|_| io::Error::other("read-ahead exceeds seek range"))?;
                    let chunk = buf[..buf.len().min(POLL_IO_CHUNK_BYTES)].to_vec();
                    let future = this.submit_blocking(move |file| {
                        let mut file_ref: &std::fs::File = file;
                        Seek::seek(&mut file_ref, SeekFrom::Current(-rewind))?;
                        Write::write(&mut file_ref, &chunk)
                    });
                    *pending = Some(PendingIo::Write { future });
                }
                other => {
                    *pending = other;
                    match Self::settle_foreign_pending(&mut pending, poll_cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {}
                    }
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, poll_cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut pending = this.pending.lock();
        loop {
            match pending.take() {
                Some(PendingIo::Flush { mut future }) => match future.as_mut().poll(poll_cx) {
                    Poll::Pending => {
                        *pending = Some(PendingIo::Flush { future });
                        return Poll::Pending;
                    }
                    Poll::Ready(result) => return Poll::Ready(result),
                },
                // Flushing does not move the cursor, so read-ahead survives.
                Some(PendingIo::ReadAhead { bytes, consumed }) => {
                    *pending = Some(PendingIo::ReadAhead { bytes, consumed });
                    return Poll::Ready(Ok(()));
                }
                None => {
                    let future = this.submit_blocking(|file| {
                        let mut file_ref: &std::fs::File = file;
                        Write::flush(&mut file_ref)
                    });
                    *pending = Some(PendingIo::Flush { future });
                }
                other => {
                    *pending = other;
                    match Self::settle_foreign_pending(&mut pending, poll_cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {}
                    }
                }
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncSeek for File {
    fn poll_seek(
        self: Pin<&mut Self>,
        poll_cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        let this = self.get_mut();
        let mut pending = this.pending.lock();
        loop {
            match pending.take() {
                Some(PendingIo::Seek { mut future }) => match future.as_mut().poll(poll_cx) {
                    Poll::Pending => {
                        *pending = Some(PendingIo::Seek { future });
                        return Poll::Pending;
                    }
                    Poll::Ready(result) => return Poll::Ready(result),
                },
                None => {
                    let future = this.submit_blocking(move |file| {
                        let mut file_ref: &std::fs::File = file;
                        Seek::seek(&mut file_ref, pos)
                    });
                    *pending = Some(PendingIo::Seek { future });
                }
                Some(read_ahead @ PendingIo::ReadAhead { .. }) => {
                    // Discard unconsumed read-ahead; a relative seek is
                    // measured from where the caller believes the cursor is.
                    let unconsumed = Self::unconsumed_read_ahead(&Some(read_ahead));
                    let adjusted = match pos {
                        SeekFrom::Current(offset) => {
                            let unconsumed = i64::try_from(unconsumed)
                                .map_err(|_| io::Error::other("read-ahead exceeds seek range"))?;
                            SeekFrom::Current(offset - unconsumed)
                        }
                        absolute => absolute,
                    };
                    let future = this.submit_blocking(move |file| {
                        let mut file_ref: &std::fs::File = file;
                        Seek::seek(&mut file_ref, adjusted)
                    });
                    *pending = Some(PendingIo::Seek { future });
                }
                other => {
                    *pending = other;
                    match Self::settle_foreign_pending(&mut pending, poll_cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {}
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::io::{AsyncReadExt, AsyncWriteExt}; // Extension traits for read_to_string etc
    use tempfile::tempdir;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_file_create_write_read() {
        init_test("test_file_create_write_read");
        // Phase 0 is synchronous; we use a simple block_on for async tests.

        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("test.txt");

            // Create and write
            let mut file = File::create(&path).await.unwrap();
            file.write_all(b"hello world").await.unwrap();
            file.sync_all().await.unwrap();
            drop(file);

            // Read back
            let mut file = File::open(&path).await.unwrap();
            let mut contents = String::new();
            file.read_to_string(&mut contents).await.unwrap();
            crate::assert_with_log!(
                contents == "hello world",
                "contents",
                "hello world",
                contents
            );
        });
        crate::test_complete!("test_file_create_write_read");
    }

    #[test]
    fn test_file_seek() {
        init_test("test_file_seek");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("test_seek.txt");

            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(&path)
                .await
                .unwrap();

            file.write_all(b"0123456789").await.unwrap();

            file.seek(SeekFrom::Start(5)).await.unwrap();
            let mut buf = [0u8; 5];
            file.read_exact(&mut buf).await.unwrap();
            crate::assert_with_log!(&buf == b"56789", "seek contents", b"56789", buf);
        });
        crate::test_complete!("test_file_seek");
    }

    #[test]
    fn test_file_read_into_vec_reuses_owned_buffer() {
        init_test("test_file_read_into_vec_reuses_owned_buffer");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("test_read_into_vec.txt");
            std::fs::write(&path, b"abcdefg").unwrap();

            let mut file = File::open(&path).await.unwrap();
            let buffer = vec![0_u8; 4];
            let capacity = buffer.capacity();

            let (buffer, bytes_read) = file.read_into_vec(buffer).await.unwrap();
            crate::assert_with_log!(bytes_read == 4, "first bytes read", 4usize, bytes_read);
            crate::assert_with_log!(
                &buffer[..bytes_read] == b"abcd",
                "first chunk",
                b"abcd",
                &buffer[..bytes_read]
            );
            crate::assert_with_log!(
                buffer.capacity() == capacity,
                "buffer capacity reused",
                capacity,
                buffer.capacity()
            );

            let (buffer, bytes_read) = file.read_into_vec(buffer).await.unwrap();
            crate::assert_with_log!(bytes_read == 3, "second bytes read", 3usize, bytes_read);
            crate::assert_with_log!(
                &buffer[..bytes_read] == b"efg",
                "second chunk",
                b"efg",
                &buffer[..bytes_read]
            );
        });
        crate::test_complete!("test_file_read_into_vec_reuses_owned_buffer");
    }

    #[test]
    fn test_file_create_new_is_exclusive_and_read_write() {
        init_test("test_file_create_new_is_exclusive_and_read_write");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("exclusive.txt");

            let mut file = File::create_new(&path).await.unwrap();
            file.write_all(b"exclusive").await.unwrap();
            file.rewind().await.unwrap();

            let mut contents = String::new();
            file.read_to_string(&mut contents).await.unwrap();
            crate::assert_with_log!(
                contents == "exclusive",
                "create_new file is read-write",
                "exclusive",
                contents
            );
            drop(file);

            let err = File::create_new(&path)
                .await
                .expect_err("second create_new must fail");
            crate::assert_with_log!(
                err.kind() == io::ErrorKind::AlreadyExists,
                "create_new existing error kind",
                io::ErrorKind::AlreadyExists,
                err.kind()
            );
        });
        crate::test_complete!("test_file_create_new_is_exclusive_and_read_write");
    }

    #[test]
    fn test_file_metadata() {
        init_test("test_file_metadata");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("test_metadata.txt");

            // Create file with known content
            let mut file = File::create(&path).await.unwrap();
            file.write_all(b"test content").await.unwrap();
            file.sync_all().await.unwrap();
            drop(file);

            // Read metadata
            let file = File::open(&path).await.unwrap();
            let metadata = file.metadata().await.unwrap();

            crate::assert_with_log!(metadata.is_file(), "is_file", true, metadata.is_file());
            crate::assert_with_log!(metadata.len() == 12, "file length", 12u64, metadata.len());
        });
        crate::test_complete!("test_file_metadata");
    }

    #[test]
    fn test_file_metadata_permissions_roundtrip_uses_fs_wrapper() {
        init_test("test_file_metadata_permissions_roundtrip_uses_fs_wrapper");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("test_metadata_permissions.txt");

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .await
                .unwrap();

            let mut permissions = file.metadata().await.unwrap().permissions();
            permissions.set_readonly(true);
            file.set_permissions(permissions).await.unwrap();
            let readonly = file.metadata().await.unwrap().permissions().readonly();
            crate::assert_with_log!(
                readonly,
                "file permissions set readonly through fs wrapper",
                true,
                readonly
            );

            let mut permissions = file.metadata().await.unwrap().permissions();
            permissions.set_readonly(false);
            file.set_permissions(permissions).await.unwrap();
            let readonly = file.metadata().await.unwrap().permissions().readonly();
            crate::assert_with_log!(
                !readonly,
                "file permissions reset through fs wrapper",
                false,
                readonly
            );
        });
        crate::test_complete!("test_file_metadata_permissions_roundtrip_uses_fs_wrapper");
    }

    #[test]
    fn test_file_set_len() {
        init_test("test_file_set_len");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("test_truncate.txt");

            // Create and write using async API
            let mut file = File::create(&path).await.unwrap();
            file.write_all(b"hello world").await.unwrap();
            file.sync_all().await.unwrap();

            // Truncate
            file.set_len(5).await.unwrap();
            file.sync_all().await.unwrap();
            drop(file);

            // Verify
            let mut file = File::open(&path).await.unwrap();
            let mut contents = String::new();
            file.read_to_string(&mut contents).await.unwrap();
            crate::assert_with_log!(contents == "hello", "truncated contents", "hello", contents);
        });
        crate::test_complete!("test_file_set_len");
    }

    #[test]
    fn test_cancellation_safety_soft_cancel() {
        // Test that dropping an in-flight file operation doesn't corrupt state.
        // With spawn_blocking, the blocking op continues but result is discarded.
        init_test("test_cancellation_safety_soft_cancel");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("test_cancel.txt");

            // Create file first
            let file = File::create(&path).await.unwrap();
            drop(file);

            // Open the file - this should complete
            let file = File::open(&path).await.unwrap();

            // File should be usable after the operation completed
            let metadata = file.metadata().await.unwrap();
            crate::assert_with_log!(metadata.is_file(), "file exists", true, metadata.is_file());
        });
        crate::test_complete!("test_cancellation_safety_soft_cancel");
    }

    #[test]
    fn test_file_from_std_into_std_roundtrip() {
        init_test("test_file_from_std_into_std_roundtrip");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("std_roundtrip.txt");

            let std_file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .read(true)
                .open(&path)
                .unwrap();

            let file = File::from_std(std_file);
            let mut roundtrip = file.into_std().unwrap();
            roundtrip.write_all(b"std bridge").unwrap();
            roundtrip.sync_all().unwrap();
            drop(roundtrip);

            let mut file = File::open(&path).await.unwrap();
            let mut contents = String::new();
            file.read_to_string(&mut contents).await.unwrap();
            crate::assert_with_log!(
                contents == "std bridge",
                "roundtrip contents",
                "std bridge",
                contents
            );
        });
        crate::test_complete!("test_file_from_std_into_std_roundtrip");
    }

    #[test]
    fn test_file_into_std_when_shared() {
        init_test("test_file_into_std_when_shared");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("shared_into_std.txt");

            let file = File::create(&path).await.unwrap();
            let _other = file.try_clone().await.unwrap();
            let std_file = file.into_std().unwrap();
            let len = std_file.metadata().unwrap().len();
            crate::assert_with_log!(len == 0, "shared into_std len", 0u64, len);
        });
        crate::test_complete!("test_file_into_std_when_shared");
    }

    #[test]
    fn test_shared_arc_file_handles_support_seek_and_async_read() {
        init_test("test_shared_arc_file_handles_support_seek_and_async_read");
        futures_lite::future::block_on(async {
            let dir = tempdir().unwrap();
            let path = dir.path().join("shared_arc_seek_read.txt");
            std::fs::write(&path, b"0123456789").unwrap();

            let std_file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            let shared = Arc::new(std_file);

            let mut seeker = File {
                inner: Arc::clone(&shared),
                cursor_gate: Arc::new(Mutex::new(())),
                pending: Mutex::new(None),
                #[cfg(feature = "test-internals")]
                cursor_probe: None,
            };
            let mut reader = File {
                inner: Arc::clone(&shared),
                cursor_gate: Arc::clone(&seeker.cursor_gate),
                pending: Mutex::new(None),
                #[cfg(feature = "test-internals")]
                cursor_probe: None,
            };

            seeker.seek(SeekFrom::Start(5)).await.unwrap();
            let mut buf = [0u8; 5];
            reader.read_exact(&mut buf).await.unwrap();
            crate::assert_with_log!(
                &buf == b"56789",
                "shared handle seek/read contents",
                b"56789",
                buf
            );
        });
        crate::test_complete!("test_shared_arc_file_handles_support_seek_and_async_read");
    }
}
