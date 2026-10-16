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
//! Restricting task-spawn authority does not change this I/O placement: an
//! inherited pool still services file operations without exposing its handle.
//! A `RuntimeBuilder` configures an on-demand pool by default. On a runtime
//! built without one (`blocking_threads(0, 0)`) the offload degrades to the
//! deterministic inline fallback of `spawn_blocking` on the async worker.

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
/// Exactly one operation is outstanding per handle at a time. A caller that
/// retries after `Pending` passes the same bytes or position again. A call
/// that does not match is a new operation whose predecessor's future was
/// dropped (a timed-out `write_all`, say): the abandoned syscall still
/// commits, so it is settled first and its result is not credited to the
/// new call.
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
    /// Combined reconciliation and owned cursor operation retained by the
    /// file. Retain the bytes until the rewind succeeds.
    Rewind {
        future: PollIoFuture<()>,
        bytes: Vec<u8>,
        consumed: usize,
    },
    Write {
        future: PollIoFuture<usize>,
        /// The submitted bytes; a retry's buffer starts with them.
        chunk: Arc<Vec<u8>>,
        /// Read-ahead of a combined rewind-then-write job.
        restore: Option<RewindRestore>,
    },
    Flush {
        future: PollIoFuture<()>,
    },
    Seek {
        future: PollIoFuture<u64>,
        /// The requested position; a retry asks for the same one.
        pos: SeekFrom,
        /// Read-ahead of a combined rewind-then-seek job.
        restore: Option<RewindRestore>,
    },
}

/// Read-ahead behind a poll-trait write or seek submitted as one job that
/// first rewinds the OS cursor over it. One job keeps an abandoned operation
/// whole: whatever settles it later finds it done, not just its rewind. If
/// the rewind itself fails (a pipe or socket cannot seek back), the cursor
/// still sits past these bytes, so they are handed back as read-ahead.
struct RewindRestore {
    bytes: Vec<u8>,
    consumed: usize,
    /// Set by the job once its rewind succeeded.
    rewound: Arc<AtomicBool>,
}

impl RewindRestore {
    /// After the job failed: restore the read-ahead unless the rewind ran.
    fn restore_unless_rewound(self, pending: &mut Option<PendingIo>) {
        if !self.rewound.load(Ordering::Acquire) {
            *pending = Some(PendingIo::ReadAhead {
                bytes: self.bytes,
                consumed: self.consumed,
            });
        }
    }

    /// Bytes the OS cursor still sits past once the job ended: all the
    /// unconsumed read-ahead if it failed before its rewind ran.
    fn unrewound(restore: Option<Self>, failed: bool) -> usize {
        match restore {
            Some(restore) if failed && !restore.rewound.load(Ordering::Acquire) => {
                restore.bytes.len() - restore.consumed
            }
            _ => 0,
        }
    }
}

/// A poll-trait write that a read, flush or owned operation settled before
/// its caller polled it again. Reads and writes interleave on one handle
/// under `copy_bidirectional` or `split`; crediting the retry from here keeps
/// it from submitting the same bytes a second time.
struct SettledWrite {
    chunk: Arc<Vec<u8>>,
    written: usize,
}

impl fmt::Debug for PendingIo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { .. } => f.write_str("PendingIo::Read"),
            Self::ReadAhead { bytes, consumed } => f
                .debug_struct("PendingIo::ReadAhead")
                .field("remaining", &(bytes.len() - consumed))
                .finish(),
            Self::Rewind { .. } => f.write_str("PendingIo::Rewind"),
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
    /// A write settled by another operation, awaiting its caller's retry.
    /// Locked only while `pending` is held.
    settled_write: Mutex<Option<SettledWrite>>,
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

    async fn with_cursor_inner<R, F>(&mut self, op: F) -> io::Result<R>
    where
        R: Send + 'static,
        F: FnOnce(Arc<std::fs::File>) -> io::Result<R> + Send + 'static,
    {
        // The poll-based traits may have a syscall in flight or read-ahead
        // bytes the caller never consumed; both move the OS cursor past where
        // the caller believes it is. Settle them first so this owned cursor
        // operation observes the caller's cursor.
        self.settle_trait_pending().await?;
        let read_ahead = {
            let mut pending = self.pending.lock();
            if let Some(PendingIo::ReadAhead { bytes, consumed }) = pending.as_mut() {
                let rewind = i64::try_from(bytes.len() - *consumed)
                    .map_err(|_| io::Error::other("read-ahead exceeds seek range"))?;
                let bytes = std::mem::take(bytes);
                let consumed = *consumed;
                *pending = None;
                (rewind != 0).then_some((rewind, bytes, consumed))
            } else {
                None
            }
        };
        let inner = Arc::clone(&self.inner);
        let cursor_gate = Arc::clone(&self.cursor_gate);
        #[cfg(feature = "test-internals")]
        let cursor_probe = self.cursor_probe.clone();

        if let Some((rewind, bytes, consumed)) = read_ahead {
            // Cancelling the caller may discard an operation that has not
            // acquired the cursor gate, but it must not discard the rewind.
            struct CancelBeforeStart<T>(Arc<Mutex<Option<T>>>);
            impl<T> Drop for CancelBeforeStart<T> {
                fn drop(&mut self) {
                    let operation = self.0.lock().take();
                    drop(operation);
                }
            }

            let operation = Arc::new(Mutex::new(Some(op)));
            let _cancel_before_start = CancelBeforeStart(Arc::clone(&operation));
            let result = Arc::new(Mutex::new(None));
            let task_result = Arc::clone(&result);
            let future = Box::pin(async move {
                let completed = spawn_blocking_io(move || {
                    #[cfg(feature = "test-internals")]
                    if let Some(probe) = &cursor_probe {
                        probe.before_gate();
                    }

                    let _cursor_guard = cursor_gate.lock();
                    let operation = operation.lock().take();

                    #[cfg(feature = "test-internals")]
                    if let Some(probe) = &cursor_probe {
                        probe.after_gate();
                    }

                    // Keep reconciliation and the requested operation under
                    // one gate so cloned handles cannot interleave them.
                    let mut file_ref: &std::fs::File = &inner;
                    Seek::seek(&mut file_ref, SeekFrom::Current(-rewind))?;
                    Ok(operation.map(|operation| operation(inner)))
                })
                .await?;
                *task_result.lock() = completed;
                Ok(())
            });
            *self.pending.lock() = Some(PendingIo::Rewind {
                future,
                bytes,
                consumed,
            });
            self.settle_trait_pending().await?;
            let completed = result.lock().take();
            return completed.unwrap_or_else(|| {
                Err(io::Error::other(
                    "owned cursor operation completed without a result",
                ))
            });
        }

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

            op(inner)
        })
        .await
    }

    /// Opens a file in read-only mode.
    ///
    /// See [`OpenOptions::open`] for more options.
    pub async fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        crate::cx::io_gate::require_ambient_io("fs::File::open")?;
        let path = path.as_ref().to_owned();
        let file = spawn_blocking_io(move || std::fs::File::open(&path)).await?;
        Ok(Self::from_std(file))
    }

    /// Opens a file in write-only mode.
    ///
    /// This function will create a file if it does not exist, and will truncate it if it does.
    /// A started open may create or truncate the path after cancellation.
    pub async fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        crate::cx::io_gate::require_ambient_io("fs::File::create")?;
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
        crate::cx::io_gate::require_ambient_io("fs::File::create_new")?;
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
            settled_write: Mutex::new(None),
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
            pending,
            settled_write: _,
            #[cfg(feature = "test-internals")]
                cursor_probe: _,
        } = self;
        // A poll-trait read still in flight, or read-ahead the caller never
        // consumed, has moved the OS cursor past the caller's position. Settle
        // it (the pool task completes on its own thread; the gate below waits
        // for the same syscall anyway) and rewind, so the escaped handle reads
        // on from where the caller left off, as the v0.4.3 wrapper did.
        let rewind = Self::settle_pending_blocking(pending.into_inner())?;
        let _cursor_guard = cursor_gate.lock();
        if rewind != 0 {
            let mut file_ref: &std::fs::File = &inner;
            Seek::seek(&mut file_ref, SeekFrom::Current(-rewind))?;
        }
        match Arc::try_unwrap(inner) {
            Ok(file) => Ok(file),
            Err(shared) => shared.try_clone(),
        }
    }

    /// Synchronous counterpart of [`File::settle_trait_pending`] for the
    /// consuming `into_std` path: drives an outstanding poll-trait syscall to
    /// completion and returns how many bytes the OS cursor sits past the
    /// caller's position. A committed write, flush, or seek is the caller's
    /// cursor (started syscalls commit); only read bytes the caller never
    /// received count.
    fn settle_pending_blocking(pending: Option<PendingIo>) -> io::Result<i64> {
        let unconsumed = match pending {
            None => 0,
            Some(PendingIo::ReadAhead { bytes, consumed }) => bytes.len() - consumed,
            Some(PendingIo::Read { future }) => {
                futures_lite::future::block_on(future).map_or(0, |bytes| bytes.len())
            }
            Some(PendingIo::Rewind { future, .. }) => {
                futures_lite::future::block_on(future)?;
                0
            }
            Some(PendingIo::Write {
                future, restore, ..
            }) => {
                let failed = futures_lite::future::block_on(future).is_err();
                RewindRestore::unrewound(restore, failed)
            }
            Some(PendingIo::Flush { future }) => {
                let _ = futures_lite::future::block_on(future);
                0
            }
            Some(PendingIo::Seek {
                future, restore, ..
            }) => {
                let failed = futures_lite::future::block_on(future).is_err();
                RewindRestore::unrewound(restore, failed)
            }
        };
        i64::try_from(unconsumed).map_err(|_| io::Error::other("read-ahead exceeds seek range"))
    }

    /// Attempts to sync all OS-internal metadata to disk.
    ///
    /// A started sync may finish after the returned future is dropped. A
    /// poll-trait write still in flight (its future dropped) lands first.
    pub async fn sync_all(&self) -> io::Result<()> {
        self.settle_trait_pending().await?;
        self.with_inner(|inner| inner.sync_all()).await
    }

    /// This function is similar to `sync_all`, except that it will not sync file metadata.
    /// A started sync may finish after the returned future is dropped.
    pub async fn sync_data(&self) -> io::Result<()> {
        self.settle_trait_pending().await?;
        self.with_inner(|inner| inner.sync_data()).await
    }

    /// Truncates or extends the underlying file.
    ///
    /// This uses soft cancellation. A started resize may commit after the
    /// returned future is dropped. A poll-trait write still in flight lands
    /// before the resize.
    pub async fn set_len(&self, size: u64) -> io::Result<()> {
        self.settle_trait_pending().await?;
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
    ///
    /// Each wrapper settles only its own poll-trait state: read-ahead held by
    /// one clone (a read whose future was dropped mid-flight) is invisible to
    /// the other, whose next cursor operation starts past those bytes. Use one
    /// wrapper per logical reader, as with duplicated `std::fs::File` handles.
    pub async fn try_clone(&self) -> io::Result<Self> {
        let file = self.with_inner(|inner| inner.try_clone()).await?;
        Ok(Self {
            inner: Arc::new(file),
            cursor_gate: Arc::clone(&self.cursor_gate),
            pending: Mutex::new(None),
            settled_write: Mutex::new(None),
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

// Poll-based traits offload bounded syscalls when a blocking pool is present,
// retaining the inline fallback otherwise. Shared handles use the same cursor
// gate as the owned operations, including while a started syscall settles.

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
        #[cfg(feature = "test-internals")]
        let cursor_probe = self.cursor_probe.clone();
        let run = move || {
            #[cfg(feature = "test-internals")]
            if let Some(probe) = &cursor_probe {
                probe.before_gate();
            }
            let _cursor_guard = cursor_gate.lock();
            #[cfg(feature = "test-internals")]
            if let Some(probe) = &cursor_probe {
                probe.after_gate();
            }
            op(&inner)
        };
        // Offload only when a runtime blocking pool exists. Outside a runtime,
        // or inside one built without a pool, run the syscall inline and
        // resolve immediately: that is the previous (phase-0 sync) behaviour
        // the owned cursor methods and `fs::file_concurrent_test` rely on, and
        // it avoids parking a caller that has no executor to wake it.
        // File I/O is already admitted independently of SPAWN. Use the stored
        // placement, as spawn_blocking does, without granting the caller a
        // public submission handle or restoring any restricted capability.
        match crate::cx::Cx::current().and_then(|cx| cx.blocking_pool_handle_for_inheritance()) {
            Some(pool) => Box::pin(crate::runtime::spawn_blocking::spawn_blocking_on_pool(
                pool, run,
            )),
            None => Box::pin(std::future::ready(run())),
        }
    }

    /// Drives an outstanding operation that belongs to a *different* trait
    /// call (for example a write whose future the caller dropped mid-flight)
    /// to a settled state before a new operation starts, so no started
    /// syscall is ever lost or reordered. A completed read settles as
    /// read-ahead bytes; a completed write, flush, or seek settles as `None`.
    /// With `retain`, a completed write's count is kept there for its caller's
    /// retry (see [`SettledWrite`]).
    fn settle_foreign_pending(
        pending: &mut Option<PendingIo>,
        retain: Option<&mut Option<SettledWrite>>,
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
            Some(PendingIo::Rewind {
                mut future,
                bytes,
                consumed,
            }) => match future.as_mut().poll(poll_cx) {
                Poll::Pending => {
                    *pending = Some(PendingIo::Rewind {
                        future,
                        bytes,
                        consumed,
                    });
                    Poll::Pending
                }
                Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
                Poll::Ready(Err(error)) => {
                    *pending = Some(PendingIo::ReadAhead { bytes, consumed });
                    Poll::Ready(Err(error))
                }
            },
            Some(PendingIo::Write {
                mut future,
                chunk,
                restore,
            }) => match future.as_mut().poll(poll_cx) {
                Poll::Pending => {
                    *pending = Some(PendingIo::Write {
                        future,
                        chunk,
                        restore,
                    });
                    Poll::Pending
                }
                // The bytes were committed to the file, which is the documented
                // "started syscall commits" behaviour. A read, flush or owned
                // operation keeps the count for the write's caller: under
                // copy_bidirectional or split it is still polling and would
                // otherwise submit the same bytes again (br-asupersync-pxg07b).
                Poll::Ready(result) => {
                    if let (Ok(written), Some(slot)) = (&result, retain) {
                        *slot = Some(SettledWrite {
                            chunk,
                            written: *written,
                        });
                    }
                    if let (Err(_), Some(restore)) = (&result, restore) {
                        restore.restore_unless_rewound(pending);
                    }
                    Poll::Ready(result.map(|_| ()))
                }
            },
            Some(PendingIo::Flush { mut future }) => match future.as_mut().poll(poll_cx) {
                Poll::Pending => {
                    *pending = Some(PendingIo::Flush { future });
                    Poll::Pending
                }
                Poll::Ready(result) => Poll::Ready(result),
            },
            Some(PendingIo::Seek {
                mut future,
                pos,
                restore,
            }) => match future.as_mut().poll(poll_cx) {
                Poll::Pending => {
                    *pending = Some(PendingIo::Seek {
                        future,
                        pos,
                        restore,
                    });
                    Poll::Pending
                }
                Poll::Ready(result) => {
                    if let (Err(_), Some(restore)) = (&result, restore) {
                        restore.restore_unless_rewound(pending);
                    }
                    Poll::Ready(result.map(|_| ()))
                }
            },
        }
    }

    /// Number of read-ahead bytes the OS cursor is already past but the
    /// caller has not consumed. Writes and relative seeks compensate for it.
    fn unconsumed_read_ahead(pending: Option<&PendingIo>) -> usize {
        match pending {
            Some(PendingIo::ReadAhead { bytes, consumed }) => bytes.len() - consumed,
            _ => 0,
        }
    }

    /// Settles outstanding syscalls without discarding read-ahead. Internal
    /// rewind futures remain owned by the file if the caller is dropped.
    async fn settle_trait_pending(&self) -> io::Result<()> {
        std::future::poll_fn(|poll_cx| {
            let mut pending = self.pending.lock();
            Self::settle_foreign_pending(&mut pending, None, poll_cx)
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
                    let mut settled = this.settled_write.lock();
                    match Self::settle_foreign_pending(&mut pending, Some(&mut *settled), poll_cx) {
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
        // A write another operation settled before this retry already
        // committed its bytes: report it instead of writing them again. Any
        // other write means it was abandoned.
        if let Some(settled) = this.settled_write.lock().take()
            && buf.starts_with(&settled.chunk)
        {
            return Poll::Ready(Ok(settled.written));
        }
        loop {
            match pending.take() {
                // A retry passes the same bytes, so its buffer starts with
                // the submitted chunk. Anything else is a new write after an
                // abandoned one, settled below by the catch-all arm.
                Some(PendingIo::Write {
                    mut future,
                    chunk,
                    restore,
                }) if buf.starts_with(&chunk) => match future.as_mut().poll(poll_cx) {
                    Poll::Pending => {
                        *pending = Some(PendingIo::Write {
                            future,
                            chunk,
                            restore,
                        });
                        return Poll::Pending;
                    }
                    Poll::Ready(result) => {
                        if let (Err(_), Some(restore)) = (&result, restore) {
                            restore.restore_unless_rewound(&mut pending);
                        }
                        return Poll::Ready(result);
                    }
                },
                None => {
                    // A caller retries with the same bytes until `Ready`, so
                    // the chunk is copied once and the count of that chunk is
                    // reported on completion.
                    let chunk = Arc::new(buf[..buf.len().min(POLL_IO_CHUNK_BYTES)].to_vec());
                    let submitted = Arc::clone(&chunk);
                    let future = this.submit_blocking(move |file| {
                        let mut file_ref: &std::fs::File = file;
                        Write::write(&mut file_ref, &submitted)
                    });
                    *pending = Some(PendingIo::Write {
                        future,
                        chunk,
                        restore: None,
                    });
                }
                Some(read_ahead) if matches!(read_ahead, PendingIo::ReadAhead { .. }) => {
                    // The OS cursor sits past bytes the caller never consumed;
                    // rewind before writing so the write lands where the
                    // caller believes the cursor is. One job, so an abandoned
                    // write is settled whole; a failed rewind (a pipe or
                    // socket) hands the unconsumed read-ahead back.
                    let rewind = i64::try_from(Self::unconsumed_read_ahead(Some(&read_ahead)))
                        .map_err(|_| io::Error::other("read-ahead exceeds seek range"))?;
                    let PendingIo::ReadAhead { bytes, consumed } = read_ahead else {
                        unreachable!()
                    };
                    let chunk = Arc::new(buf[..buf.len().min(POLL_IO_CHUNK_BYTES)].to_vec());
                    let submitted = Arc::clone(&chunk);
                    let rewound = Arc::new(AtomicBool::new(false));
                    let job_rewound = Arc::clone(&rewound);
                    let future = this.submit_blocking(move |file| {
                        let mut file_ref: &std::fs::File = file;
                        Seek::seek(&mut file_ref, SeekFrom::Current(-rewind))?;
                        job_rewound.store(true, Ordering::Release);
                        Write::write(&mut file_ref, &submitted)
                    });
                    *pending = Some(PendingIo::Write {
                        future,
                        chunk,
                        restore: Some(RewindRestore {
                            bytes,
                            consumed,
                            rewound,
                        }),
                    });
                }
                other => {
                    *pending = other;
                    match Self::settle_foreign_pending(&mut pending, None, poll_cx) {
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
                    let mut settled = this.settled_write.lock();
                    match Self::settle_foreign_pending(&mut pending, Some(&mut *settled), poll_cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {}
                    }
                }
            }
        }
    }

    /// Files have no protocol-level shutdown; this settles any poll-trait
    /// write still in flight so its error is reported here instead of being
    /// lost when the handle is dropped, then flushes.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
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
        // A write retried after the cursor moves is a new write, not a retry.
        this.settled_write.lock().take();
        loop {
            match pending.take() {
                // A retry asks for the same position. A different one is a new
                // seek after an abandoned one, settled by the catch-all arm.
                Some(PendingIo::Seek {
                    mut future,
                    pos: submitted,
                    restore,
                }) if submitted == pos => match future.as_mut().poll(poll_cx) {
                    Poll::Pending => {
                        *pending = Some(PendingIo::Seek {
                            future,
                            pos,
                            restore,
                        });
                        return Poll::Pending;
                    }
                    Poll::Ready(result) => {
                        if let (Err(_), Some(restore)) = (&result, restore) {
                            restore.restore_unless_rewound(&mut pending);
                        }
                        return Poll::Ready(result);
                    }
                },
                None => {
                    let future = this.submit_blocking(move |file| {
                        let mut file_ref: &std::fs::File = file;
                        Seek::seek(&mut file_ref, pos)
                    });
                    *pending = Some(PendingIo::Seek {
                        future,
                        pos,
                        restore: None,
                    });
                }
                Some(read_ahead) if matches!(read_ahead, PendingIo::ReadAhead { .. }) => {
                    // Reconcile the physical cursor before the requested
                    // seek, as the owned seek path does, in the same job: an
                    // abandoned seek is then settled whole, not just its
                    // rewind. A failed rewind (a pipe or socket) hands the
                    // unconsumed read-ahead back; once the rewind ran, the
                    // cursor is where the caller believes it is.
                    let unconsumed = i64::try_from(Self::unconsumed_read_ahead(Some(&read_ahead)))
                        .map_err(|_| io::Error::other("read-ahead exceeds seek range"))?;
                    let PendingIo::ReadAhead { bytes, consumed } = read_ahead else {
                        unreachable!()
                    };
                    let rewound = Arc::new(AtomicBool::new(false));
                    let job_rewound = Arc::clone(&rewound);
                    let future = this.submit_blocking(move |file| {
                        let mut file_ref: &std::fs::File = file;
                        Seek::seek(&mut file_ref, SeekFrom::Current(-unconsumed))?;
                        job_rewound.store(true, Ordering::Release);
                        Seek::seek(&mut file_ref, pos)
                    });
                    *pending = Some(PendingIo::Seek {
                        future,
                        pos,
                        restore: Some(RewindRestore {
                            bytes,
                            consumed,
                            rewound,
                        }),
                    });
                }
                other => {
                    *pending = other;
                    match Self::settle_foreign_pending(&mut pending, None, poll_cx) {
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
#[path = "file_inline_tests.rs"]
mod tests;
